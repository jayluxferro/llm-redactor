"""FastAPI-based HTTP proxy — OpenAI-compatible + Anthropic Messages API.

Supports both non-streaming and streaming (SSE) requests.  For streaming,
the proxy buffers content deltas, restores placeholders in the accumulated
text, and re-emits corrected SSE chunks.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..config import Config
from ..detect.types import Span
from ..image.redactor import ImageRedactionUnavailable, InvalidImage, OnnxImageRedactor
from ..observability import log_event
from ..pipeline.option_b import OptionBPipeline, RefusalError
from ..redact.placeholder import PlaceholderGenerator, redact
from ..redact.raw_surgery import (
    RawRedaction,
    SSETextRestorer,
    SurgeryError,
    redact_signed_request,
    restore_response_bytes,
)
from ..redact.restore import restore
from ..transport.cloud import (
    StreamResult,
    forward_anthropic_messages,
    forward_anthropic_messages_stream,
    forward_anthropic_raw,
    forward_anthropic_raw_stream,
    forward_chat_completion_stream,
)


def _placeholder_session_tag(body: dict[str, Any], pipeline: OptionBPipeline) -> str | None:
    """Session tag for placeholders: per-request random, or stable per conversation.

    Per-conversation tags keep redacted bytes identical across a session's
    turns — required for upstream prompt caching to see a stable prefix.
    """
    if not pipeline.config.pipeline.placeholder_request_tag:
        return None
    mode = getattr(pipeline.config.pipeline, "placeholder_tag_mode", "per_request")
    if mode != "per_conversation":
        return secrets.token_hex(4)
    system = body.get("system")
    if isinstance(system, list):
        system_text = "\n".join(
            block.get("text", "") for block in system if isinstance(block, dict)
        )
    else:
        system_text = system if isinstance(system, str) else ""
    first_user = ""
    for message in body.get("messages") or []:
        if message.get("role") == "user":
            content = message.get("content", "")
            first_user = (
                content if isinstance(content, str) else json.dumps(content, sort_keys=True)
            )
            break
    seed = json.dumps({"s": system_text, "u": first_user}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def _body_has_signed_blocks(body: dict[str, Any]) -> bool:
    """True if any message in the body has a thinking / redacted_thinking block.

    Anthropic validates these blocks against the JSON encoding it served;
    any json.loads/dumps round-trip in the chain breaks the signature.
    Callers must forward such requests as raw bytes.
    """
    for msg in body.get("messages") or []:
        content = msg.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") in (
                    "thinking",
                    "redacted_thinking",
                ):
                    return True
    return False


app = FastAPI(title="llm-redactor", version="0.1.0")

# Initialized at startup via configure().
_pipeline: OptionBPipeline | None = None
_config: Config | None = None
_image_redactor: OnnxImageRedactor | None = None


def configure(config: Config, *, use_ner: bool = True) -> FastAPI:
    """Wire the pipeline into the app. Call before serving."""
    global _pipeline, _config, _image_redactor
    _pipeline = OptionBPipeline(config=config, use_ner=use_ner)
    _config = config
    _image_redactor = OnnxImageRedactor(config.pipeline.image_redaction)
    return app


def _get_pipeline() -> OptionBPipeline:
    if _pipeline is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _pipeline


def _get_config() -> Config:
    if _config is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _config


def _get_image_redactor() -> OnnxImageRedactor:
    if _image_redactor is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _image_redactor


logger = logging.getLogger(__name__)


# Gate 1 helper: never label a non-SSE upstream as SSE, and pass through error
# statuses with a faithful plain response.  Keep retry-after.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-encoding",
        "content-length",
    }
)


def _plain_upstream_response(result: StreamResult) -> Response:
    """Build a plain Response from an upstream preflight that was not SSE."""
    out_headers = {k: v for k, v in result.headers.items() if k.lower() not in _HOP_BY_HOP}
    return Response(
        content=result.body or b"",
        status_code=result.status_code,
        headers=out_headers,
    )


def _upstream_transport_error(exc: Exception, target: object) -> JSONResponse:
    """Map an upstream transport failure to a typed 504/502 + WARNING log.

    httpx timeouts and ReadError wrapping anyio.EndOfStream have an EMPTY
    str() — always prefix the exception type, otherwise the client gets a
    blank message and the logs stay silent (connect-path sibling of the
    Gate 2 empty-str bug class).  504 for timeouts, 502 for everything
    else, matching the rest of the manifold chain.
    """
    detail = f"{type(exc).__name__}: {exc}".rstrip(": ")
    status = 504 if isinstance(exc, httpx.TimeoutException) else 502
    etype = "upstream_timeout" if status == 504 else "upstream_error"
    logger.warning(
        "llm-redactor: upstream request to %s failed: %s",
        getattr(target, "endpoint", "?"),
        detail,
    )
    return JSONResponse(
        status_code=status,
        content={"error": {"type": etype, "message": detail}},
    )


async def _gate_2_openai(iterator: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Gate 2: emit a terminal error frame + [DONE] on mid-stream failure."""
    t0 = time.monotonic()
    nbytes = 0
    try:
        async for chunk in iterator:
            nbytes += len(chunk)
            yield chunk
    except Exception as e:
        # An abrupt upstream close surfaces as httpx.ReadError wrapping
        # anyio.EndOfStream — str(e) is EMPTY, so always prefix the
        # exception type; without it both this log line and the
        # client-visible terminal frame carry no information.
        detail = f"{type(e).__name__}: {e}".rstrip(": ")
        logger.warning(
            "llm-redactor: mid-stream failure after %.1fs / %dB: %s",
            time.monotonic() - t0,
            nbytes,
            detail,
        )
        # Leading \n\n self-frames the terminal event: if the upstream died
        # mid-frame, the partial line is terminated and its block dispatched
        # first; after a complete frame the extra blank lines are no-ops.
        err = json.dumps({"error": {"type": type(e).__name__, "message": detail}})
        yield f"\n\ndata: {err}\n\n".encode()
        yield b"data: [DONE]\n\n"


async def _gate_2_anthropic(iterator: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Gate 2: emit a single terminal `event: error` frame then close."""
    t0 = time.monotonic()
    nbytes = 0
    try:
        async for chunk in iterator:
            nbytes += len(chunk)
            yield chunk
    except Exception as e:
        # See _gate_2_openai for why the frame carries a leading \n\n
        # and why the exception type must be preserved in detail.
        detail = f"{type(e).__name__}: {e}".rstrip(": ")
        logger.warning(
            "llm-redactor: mid-stream failure after %.1fs / %dB: %s",
            time.monotonic() - t0,
            nbytes,
            detail,
        )
        err = json.dumps({"error": {"type": type(e).__name__, "message": detail}})
        yield f"\n\nevent: error\ndata: {err}\n\n".encode()


# --------------- OpenAI-compatible endpoints ---------------


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(request: Request) -> JSONResponse | Response | StreamingResponse:
    """OpenAI-compatible chat completion endpoint with redaction.

    Supports both ``stream: false`` (default) and ``stream: true``.
    """
    body: dict[str, Any] = await request.json()
    pipeline = _get_pipeline()
    config = _get_config()

    # Forward all headers from the incoming request (minus hop-by-hop).
    # accept-encoding is capability-bound: this proxy consumes upstream bytes
    # before re-serving, so it must not advertise encodings its own httpx
    # cannot decode (br/zstd) — httpx re-adds its own capability set on send.
    _skip = frozenset(
        {
            "host",
            "transfer-encoding",
            "connection",
            "content-length",
            "content-encoding",
            "accept-encoding",
        }
    )
    upstream_headers = {k: v for k, v in request.headers.items() if k.lower() not in _skip}

    # Tool-bearing requests: policy decides bypass vs refuse (redaction
    # cannot reliably span tool schemas).
    if "tools" in body or "functions" in body:
        policy = (config.transport.tools_policy or "bypass").lower()
        if policy == "refuse":
            log_event(
                "proxy_tools_refused",
                path="/v1/chat/completions",
                has_tools="tools" in body,
                has_functions="functions" in body,
            )
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "type": "redactor_refused",
                        "reason": "tools_or_functions_present",
                        "message": (
                            "This proxy cannot redact tool/function payloads safely. "
                            "Remove tools/functions, set transport.tools_policy to bypass, "
                            "or call the model without tools when using the redactor."
                        ),
                    },
                },
            )
        log_event(
            "proxy_tools_bypass",
            path="/v1/chat/completions",
            streaming=bool(body.get("stream")),
        )
        _get_pipeline()._stats["tools_bypass"] += 1
        return await _forward_openai_transparent(body, config, upstream_headers)

    # Allow per-request overrides via extra_body.redactor.
    extra = body.get("extra_body", {}).get("redactor", {})
    strict_override = extra.get("strict")
    # Resolve effective strict flag for this request without mutating shared config.
    effective_strict = (
        bool(strict_override)
        if strict_override is not None
        else pipeline.config.pipeline.opt_b_redact.strict
    )

    is_stream = body.get("stream", False)

    if is_stream:
        return await _handle_openai_stream(
            body,
            pipeline,
            config,
            upstream_headers,
            strict=effective_strict,
        )

    try:
        result = await pipeline.run(
            body,
            upstream_headers=upstream_headers,
            strict=effective_strict,
        )
    except RefusalError as e:
        return _refusal_response(e)

    # Build the response with redactor metadata.
    response_body = result.response
    response_body["redactor"] = {
        "options_applied": result.options_applied,
        "detections": _summarize_detections(result.detections),
        "leak_audit": result.leak_audit,
    }

    return JSONResponse(
        content=response_body,
        headers={"X-LLM-Redactor-Mode": "redacted"},
    )


async def _handle_openai_stream(
    body: dict[str, Any],
    pipeline: OptionBPipeline,
    config: Config,
    upstream_headers: dict[str, str] | None = None,
    *,
    strict: bool = False,
) -> Response | StreamingResponse:
    """Redact the request, stream from cloud, restore placeholders in deltas."""
    messages = body.get("messages", [])
    (
        outgoing_messages,
        redaction_results,
        stream_detections,
        ph_tag,
    ) = await pipeline.redact_chat_messages(messages)

    # Track stats (non-streaming path does this inside pipeline.run())
    pipeline._stats["requests"] += 1
    pipeline._stats["detections"] += len(stream_detections)

    # Strict mode: refuse if any detection has low confidence
    if strict:
        low_conf = [s for s in stream_detections if s.confidence < 0.5]
        if low_conf:
            pipeline._stats["refusals"] += 1
            return _refusal_response(
                RefusalError(reason="low_confidence_detection", spans=low_conf)
            )

    combined_reverse_map: dict[str, str] = {}
    for rr in redaction_results.values():
        combined_reverse_map.update(rr.reverse_map)

    log_event(
        "proxy_stream_prepared",
        detections=len(stream_detections),
        placeholder_tag=bool(ph_tag),
    )

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages
    outgoing.pop("extra_body", None)

    # Gate 1: open upstream stream and inspect headers before committing to SSE.
    upstream = await forward_chat_completion_stream(
        outgoing,
        config.cloud_target,
        upstream_headers=upstream_headers,
    )
    if upstream.iterator is None:
        return _plain_upstream_response(upstream)
    # Bind the narrowed iterator to a local: mypy discards attribute narrowing
    # inside closures, and the async generators below close over it.
    iterator = upstream.iterator

    async def generate() -> AsyncIterator[bytes]:
        # Accumulate redacted (upstream) assistant text so placeholders split across
        # SSE chunks still restore. Emit only the *new* restored suffix per delta.
        # We cannot slice with len(prev_restored) because completing a placeholder can
        # rewrite earlier characters (restore(prefix) is not always a text-prefix of
        # restore(prefix+suffix)); use longest common prefix between successive full
        # restores instead.
        accumulated_redacted = ""
        prev_emit_restored = ""
        last_choice_index: int | None = None

        async for chunk in iterator:
            # Parse SSE lines, restore placeholders in content deltas.
            for line in chunk.decode("utf-8", errors="replace").splitlines():
                if not line.startswith("data: "):
                    yield (line + "\n").encode()
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    yield b"data: [DONE]\n\n"
                    continue
                try:
                    event = json.loads(data)
                    for choice in event.get("choices", []):
                        idx = choice.get("index", 0)
                        if last_choice_index is not None and idx != last_choice_index:
                            accumulated_redacted = ""
                            prev_emit_restored = ""
                        last_choice_index = idx

                        delta = choice.get("delta", {})
                        piece = delta.get("content")
                        if piece and combined_reverse_map:
                            accumulated_redacted += piece
                            new_restored = restore(accumulated_redacted, combined_reverse_map)
                            lcp = 0
                            lim = min(len(prev_emit_restored), len(new_restored))
                            while lcp < lim and prev_emit_restored[lcp] == new_restored[lcp]:
                                lcp += 1
                            delta["content"] = new_restored[lcp:]
                            prev_emit_restored = new_restored
                    yield f"data: {json.dumps(event)}\n\n".encode()
                except json.JSONDecodeError:
                    yield (line + "\n").encode()

    return StreamingResponse(
        _gate_2_openai(generate()),
        media_type="text/event-stream",
        headers={"X-LLM-Redactor-Mode": "redacted"},
    )


async def _forward_openai_transparent(
    body: dict[str, Any],
    config: Config,
    headers: dict[str, str],
) -> StreamingResponse | JSONResponse | Response:
    """Transparent proxy for OpenAI tool requests — bypass redaction pipeline."""
    from ..transport.cloud import (
        forward_chat_completion,
        forward_chat_completion_stream,
    )

    bypass_headers = {
        "X-LLM-Redactor-Mode": "bypass-tools",
        "X-LLM-Redactor-Bypass-Reason": "tools-or-functions",
    }

    is_stream = body.get("stream", False)
    if is_stream:
        # Gate 1: open upstream before committing to SSE.
        upstream = await forward_chat_completion_stream(
            body,
            config.cloud_target,
            upstream_headers=headers,
        )
        if upstream.iterator is None:
            return _plain_upstream_response(upstream)

        return StreamingResponse(
            _gate_2_openai(upstream.iterator),
            media_type="text/event-stream",
            headers=bypass_headers,
        )

    try:
        resp = await forward_chat_completion(
            body,
            config.cloud_target,
            upstream_headers=headers,
        )
    except httpx.HTTPStatusError as e:
        try:
            err_body = e.response.json()
        except Exception:
            try:
                text = e.response.text[:500]
            except Exception:
                text = f"(undecodable body, {len(e.response.content)} bytes)"
            err_body = {"error": text}
        resp_headers: dict[str, str] = {}
        if ra := e.response.headers.get("retry-after"):
            resp_headers["retry-after"] = ra
        return JSONResponse(
            status_code=e.response.status_code,
            content=err_body,
            headers=resp_headers,
        )
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return JSONResponse(
            status_code=502,
            content={"error": {"type": "upstream_error", "message": str(e)}},
        )

    return JSONResponse(content=resp, headers=bypass_headers)


# --------------- Anthropic Messages endpoint ---------------


async def _handle_anthropic_stream(
    outgoing: dict[str, Any],
    config: Config,
    upstream_headers: dict[str, str],
    combined_reverse_map: dict[str, str],
    all_detections: list[Span],
) -> StreamingResponse | Response:
    """Stream Anthropic SSE chunks from upstream with placeholder restoration."""
    # Gate 1: open upstream stream and inspect headers before committing to SSE.
    upstream = await forward_anthropic_messages_stream(
        outgoing, config.cloud_target, upstream_headers=upstream_headers
    )
    if upstream.iterator is None:
        return _plain_upstream_response(upstream)

    return StreamingResponse(
        _gate_2_anthropic(upstream.iterator),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-LLM-Redactor-Mode": "redacted",
        },
    )


@app.post("/v1/messages", response_model=None)
async def anthropic_messages(request: Request) -> JSONResponse | StreamingResponse | Response:
    """Anthropic Messages API endpoint with redaction.

    Redacts content blocks in the request, forwards to the Anthropic
    endpoint, and restores placeholders in the response.

    If the request carries any ``thinking`` / ``redacted_thinking`` blocks,
    Anthropic validates their signatures against the original JSON bytes —
    any json.loads/dumps round-trip breaks them with a 400.  In that case
    we forward the raw inbound bytes unchanged and skip redaction entirely.
    """
    raw_body = await request.body()
    try:
        body: dict[str, Any] = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"type": "invalid_request_error", "message": str(e)}},
        )

    pipeline = _get_pipeline()
    config = _get_config()

    # Forward all headers from the incoming request (minus hop-by-hop).
    _skip_hop = frozenset(
        {"host", "transfer-encoding", "connection", "content-length", "content-encoding"}
    )
    raw_passthrough_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _skip_hop
    }

    # Signed Anthropic blocks → surgical redaction on the raw bytes. A JSON
    # round-trip would break the block signatures, so eligible text spans are
    # spliced out at the byte level, leaving signed regions untouched. If
    # nothing redactable is found — or surgery is impossible — fall back to
    # the original raw passthrough behaviour.
    if isinstance(body, dict) and _body_has_signed_blocks(body):
        pipeline._stats["requests"] += 1
        gen = PlaceholderGenerator(session_tag=_placeholder_session_tag(body, pipeline))
        surgical: RawRedaction | None = None
        try:
            surgical = await redact_signed_request(raw_body, pipeline.detect_spans, gen)
        except SurgeryError as exc:
            pipeline._stats["surgery_failed"] += 1
            log_event("proxy_anthropic_surgery_failed", error=str(exc)[:200])
        if surgical is not None and surgical.detections:
            pipeline._stats["detections"] += len(surgical.detections)
            pipeline._stats["signed_surgical"] += 1
            if surgical.whole_token_fallbacks:
                pipeline._stats["whole_token_fallback"] += surgical.whole_token_fallbacks
            log_event(
                "proxy_anthropic_signed_surgical",
                detections=len(surgical.detections),
                whole_token_fallbacks=surgical.whole_token_fallbacks,
            )
            if body.get("stream"):
                restorer = SSETextRestorer(surgical.reverse_map)

                # Gate 1: open upstream before committing to SSE.
                try:
                    upstream = await forward_anthropic_raw_stream(
                        surgical.new_raw,
                        config.cloud_target,
                        upstream_headers=raw_passthrough_headers,
                    )
                except httpx.HTTPError as e:
                    return _upstream_transport_error(e, config.cloud_target)
                if upstream.iterator is None:
                    return _plain_upstream_response(upstream)
                # Same closure-narrowing dance as the chat path above.
                iterator = upstream.iterator

                async def stream_surgical() -> AsyncIterator[bytes]:
                    async for chunk in iterator:
                        yield restorer.feed_chunk(chunk)
                    yield restorer.flush()

                return StreamingResponse(
                    _gate_2_anthropic(stream_surgical()),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "X-LLM-Redactor-Mode": "signed-surgical",
                    },
                )

            try:
                resp_bytes, status, resp_headers = await forward_anthropic_raw(
                    surgical.new_raw,
                    config.cloud_target,
                    upstream_headers=raw_passthrough_headers,
                )
            except httpx.HTTPError as e:
                return _upstream_transport_error(e, config.cloud_target)
            out_headers = {
                k: v
                for k, v in resp_headers.items()
                if k.lower() not in ("transfer-encoding", "content-length", "content-encoding")
            }
            out_headers["X-LLM-Redactor-Mode"] = "signed-surgical"
            return Response(
                content=restore_response_bytes(resp_bytes, surgical.reverse_map),
                status_code=status,
                headers=out_headers,
            )

        pipeline._stats["signed_passthrough"] += 1
        log_event(
            "proxy_anthropic_signed_passthrough", message_count=len(body.get("messages") or [])
        )
        if body.get("stream"):
            # Gate 1: open upstream before committing to SSE.
            try:
                upstream = await forward_anthropic_raw_stream(
                    raw_body, config.cloud_target, upstream_headers=raw_passthrough_headers
                )
            except httpx.HTTPError as e:
                return _upstream_transport_error(e, config.cloud_target)
            if upstream.iterator is None:
                return _plain_upstream_response(upstream)

            return StreamingResponse(
                _gate_2_anthropic(upstream.iterator),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "X-LLM-Redactor-Mode": "signed-passthrough",
                },
            )

        try:
            resp_bytes, status, resp_headers = await forward_anthropic_raw(
                raw_body, config.cloud_target, upstream_headers=raw_passthrough_headers
            )
        except httpx.HTTPError as e:
            return _upstream_transport_error(e, config.cloud_target)
        out_headers = {
            k: v
            for k, v in resp_headers.items()
            if k.lower() not in ("transfer-encoding", "content-length", "content-encoding")
        }
        out_headers["X-LLM-Redactor-Mode"] = "signed-passthrough"
        return Response(
            content=resp_bytes,
            status_code=status,
            headers=out_headers,
        )

    # Redact content in each message (one placeholder tag per upstream request).
    messages = body.get("messages", [])
    combined_reverse_map: dict[str, str] = {}
    all_detections: list[Span] = []
    ph_tag = _placeholder_session_tag(body, pipeline)

    outgoing_messages = []
    gen = PlaceholderGenerator(session_tag=ph_tag)
    for msg in messages:
        content = msg.get("content", "")
        # Anthropic supports string content or list of content blocks.
        if isinstance(content, str):
            spans = await pipeline.detect_spans(content)
            all_detections.extend(spans)
            if spans:
                result = redact(content, spans, gen=gen)
                combined_reverse_map.update(result.reverse_map)
                outgoing_messages.append({**msg, "content": result.redacted_text})
            else:
                outgoing_messages.append(msg)
        elif isinstance(content, list):
            # List of content blocks [{type: "text", text: "..."}].
            new_blocks = []
            for block in content:
                if block.get("type") == "text" and "text" in block:
                    spans = await pipeline.detect_spans(block["text"])
                    all_detections.extend(spans)
                    if spans:
                        result = redact(block["text"], spans, gen=gen)
                        combined_reverse_map.update(result.reverse_map)
                        new_blocks.append({**block, "text": result.redacted_text})
                    else:
                        new_blocks.append(block)
                else:
                    new_blocks.append(block)
            outgoing_messages.append({**msg, "content": new_blocks})
        else:
            outgoing_messages.append(msg)

    if pipeline.config.pipeline.opt_b_redact.strict:
        low_conf = [s for s in all_detections if s.confidence < 0.5]
        if low_conf:
            pipeline._stats["requests"] += 1
            pipeline._stats["refusals"] += 1
            return _refusal_response(
                RefusalError(reason="low_confidence_detection", spans=low_conf)
            )

    pipeline._stats["requests"] += 1
    pipeline._stats["detections"] += len(all_detections)
    log_event(
        "proxy_anthropic_prepared",
        detections=len(all_detections),
        placeholder_tag=bool(ph_tag),
    )

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages

    # Forward all headers from the incoming request (minus hop-by-hop).
    _skip = frozenset(
        {
            "host",
            "transfer-encoding",
            "connection",
            "content-length",
            "content-encoding",
            "accept-encoding",
        }
    )
    upstream_headers = {k: v for k, v in request.headers.items() if k.lower() not in _skip}

    if body.get("stream"):
        # Client wants streaming — proxy SSE chunks through directly.
        # Placeholder restoration in streaming mode is deferred to a
        # future implementation (the OpenAI path already supports it).
        return await _handle_anthropic_stream(
            outgoing, config, upstream_headers, combined_reverse_map, all_detections
        )

    # Non-streaming path: full redact → forward → restore.
    outgoing["stream"] = False

    try:
        cloud_response = await forward_anthropic_messages(
            outgoing, config.cloud_target, upstream_headers=upstream_headers
        )
    except httpx.HTTPStatusError as e:
        # Pass through the upstream status code, body, and rate-limit headers
        # so the agent knows when to retry instead of getting a generic 502.
        try:
            err_body = e.response.json()
        except Exception:
            try:
                text = e.response.text[:500]
            except Exception:
                text = f"(undecodable body, {len(e.response.content)} bytes)"
            err_body = {"error": text}
        resp_headers = {}
        if ra := e.response.headers.get("retry-after"):
            resp_headers["retry-after"] = ra
        return JSONResponse(
            status_code=e.response.status_code,
            content=err_body,
            headers=resp_headers,
        )
    except Exception as e:
        # Transport failures land here (HTTPStatusError is handled above).
        # httpx exceptions often have an EMPTY str() — the helper types them.
        return _upstream_transport_error(e, config.cloud_target)

    # Validate the upstream response has the expected Anthropic shape.
    # An empty or malformed response (e.g. wrong endpoint URL) would
    # silently pass through and confuse the agent downstream.
    if not isinstance(cloud_response.get("content"), list):
        return JSONResponse(
            status_code=502,
            content={
                "error": (
                    "Upstream returned unexpected response shape "
                    f"(missing 'content' list): {json.dumps(cloud_response)[:500]}"
                )
            },
        )

    log_event(
        "proxy_anthropic_response",
        id=cloud_response.get("id", "?"),
        model=cloud_response.get("model", "?"),
        stop_reason=cloud_response.get("stop_reason", "?"),
        content_blocks=len(cloud_response.get("content", [])),
        input_tokens=(cloud_response.get("usage") or {}).get("input_tokens", "?"),
        output_tokens=(cloud_response.get("usage") or {}).get("output_tokens", "?"),
        response_bytes=len(json.dumps(cloud_response)),
    )

    # Restore placeholders in response content blocks.
    if combined_reverse_map:
        for block in cloud_response["content"]:
            if block.get("type") == "text" and "text" in block:
                block["text"] = restore(block["text"], combined_reverse_map)

    cloud_response["redactor"] = {
        "options_applied": ["B"],
        "detections": _summarize_detections(all_detections),
    }

    return JSONResponse(
        content=cloud_response,
        headers={"X-LLM-Redactor-Mode": "redacted"},
    )


# --------------- Shared endpoints ---------------


@app.post("/v1/redactor/detect")
async def redactor_detect(request: Request) -> JSONResponse:
    """Detection endpoint for external consumers (e.g. the Burp plugin).

    Runs the full detection pipeline (regex + NER if enabled) and returns
    all sensitive spans found in the submitted text.

    Request body:  {"text": "..."}
    Response:      [{"start": 0, "end": 5, "kind": "person",
                     "confidence": 0.92, "text": "Alice", "source": "ner"}]

    This is the endpoint you point the Burp plugin's NER endpoint field at:
        http://localhost:7789/v1/redactor/detect
    """
    raw = await request.body()
    if not raw:
        return JSONResponse(content=[])
    try:
        body: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse(content=[])
    text: str = body.get("text", "")
    if not text:
        return JSONResponse(content=[])

    pipeline = _get_pipeline()
    spans = await pipeline.detect_spans(text)

    return JSONResponse(
        content=[
            {
                "start": s.start,
                "end": s.end,
                "kind": s.kind,
                "confidence": s.confidence,
                "text": s.text,
                "source": s.source,
            }
            for s in spans
        ]
    )


def _serialize_spans(spans: list[Span]) -> list[dict[str, Any]]:
    """Serialize detector output without changing its public field names."""
    return [
        {
            "start": s.start,
            "end": s.end,
            "kind": s.kind,
            "confidence": s.confidence,
            "text": s.text,
            "source": s.source,
        }
        for s in spans
    ]


@app.post("/v1/redactor/detect-batch")
async def redactor_detect_batch(request: Request) -> JSONResponse:
    """Detect spans in an ordered batch of text fragments.

    This endpoint is additive: ``/v1/redactor/detect`` remains the compact
    single-text API.  The Burp extension uses batches so a complex JSON,
    multipart, or protobuf request only needs one local HTTP round trip.

    Request body:  {"texts": ["first", "second"]}
    Response body: {"items": [[{span...}], [{span...}]]}
    """
    try:
        body: dict[str, Any] = json.loads(await request.body() or b"{}")
    except json.JSONDecodeError:
        return JSONResponse(content={"items": []})

    texts = body.get("texts", [])
    if not isinstance(texts, list) or not all(isinstance(text, str) for text in texts):
        return JSONResponse(status_code=422, content={"error": "texts must be a list of strings"})
    if len(texts) > 1_000:
        return JSONResponse(status_code=413, content={"error": "too many text fragments"})

    pipeline = _get_pipeline()
    items = [_serialize_spans(await pipeline.detect_spans(text)) if text else [] for text in texts]
    return JSONResponse(content={"items": items})


@app.post("/v1/redactor/redact-image", response_model=None)
async def redactor_redact_image(request: Request) -> Response | JSONResponse:
    """Redact PII regions in a JPEG or PNG with the optional local ONNX model.

    The response is image bytes in the source media type. This endpoint never
    forwards image bytes to a remote model and returns 503 when image redaction
    is not configured, so a caller can safely pass the original through.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    source = await request.body()
    try:
        redacted, detections = _get_image_redactor().redact(source, media_type)
    except ImageRedactionUnavailable as exc:
        return JSONResponse(status_code=503, content={"error": str(exc)})
    except InvalidImage as exc:
        status = 413 if "maximum size" in str(exc) else 422
        return JSONResponse(status_code=status, content={"error": str(exc)})

    return Response(
        content=redacted,
        media_type=media_type,
        headers={"X-LLM-Redactor-Detections": str(len(detections))},
    )


@app.get("/v1/redactor/stats")
async def redactor_stats() -> JSONResponse:
    """Aggregate counters since process start."""
    pipeline = _get_pipeline()
    return JSONResponse(content=pipeline.stats)


@app.get("/v1/redactor/config")
async def redactor_config() -> JSONResponse:
    """Read-only view of the current config."""
    pipeline = _get_pipeline()
    cfg = pipeline.config
    return JSONResponse(
        content={
            "pipeline": {
                "opt_b_redact": {
                    "enabled": cfg.pipeline.opt_b_redact.enabled,
                    "strict": cfg.pipeline.opt_b_redact.strict,
                },
                "llm_validation": {"enabled": cfg.pipeline.llm_validation.enabled},
                "image_redaction": {
                    "enabled": cfg.pipeline.image_redaction.enabled,
                    "model_configured": bool(cfg.pipeline.image_redaction.model_path),
                },
                "placeholder_request_tag": cfg.pipeline.placeholder_request_tag,
                "placeholder_tag_mode": getattr(
                    cfg.pipeline, "placeholder_tag_mode", "per_request"
                ),
            },
            "transport": {
                "tools_policy": cfg.transport.tools_policy,
                "mcp_session_cap": cfg.transport.mcp_session_cap,
            },
            "cloud_target": {
                "backend": cfg.cloud_target.backend,
                "endpoint": cfg.cloud_target.endpoint,
            },
            "policy": {"categories": cfg.policy.categories},
        }
    )


# --------------- Helpers ---------------


def _refusal_response(e: RefusalError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "type": "redactor_refused",
                "reason": e.reason,
                "detected_spans": [
                    {
                        "kind": s.kind,
                        "text_hint": f"...{s.text[:8]}...",
                        "confidence": s.confidence,
                    }
                    for s in e.spans
                ],
                "guidance": (
                    "Review the request and mark sensitive spans manually, "
                    "or disable strict mode with extra_body.redactor.strict=false."
                ),
            },
        },
    )


def _summarize_detections(detections: list) -> list[dict[str, Any]]:
    """Group detections by kind for the response metadata."""
    counts: dict[str, int] = {}
    for d in detections:
        counts[d.kind] = counts.get(d.kind, 0) + 1
    return [{"kind": k, "count": v} for k, v in counts.items()]
