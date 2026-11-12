"""FastAPI-based HTTP proxy — OpenAI-compatible + Anthropic Messages API.

Supports both non-streaming and streaming (SSE) requests.  For streaming,
the proxy buffers content deltas, restores placeholders in the accumulated
text, and re-emits corrected SSE chunks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..config import Config, load_config
from ..detect.orchestrator import apply_detection_config
from ..detect.types import Span
from ..image.redactor import ImageRedactionUnavailable, InvalidImage, OnnxImageRedactor
from ..observability import configure_logging, log_event
from ..pipeline.option_b import OptionBPipeline, RefusalError, RequestScrubber
from ..redact.placeholder import PlaceholderGenerator
from ..redact.raw_surgery import (
    RawRedaction,
    SSETextRestorer,
    SurgeryError,
    redact_signed_request,
    restore_response_bytes,
)
from ..redact.restore import StreamRestorer, json_fragment, restore, restore_json
from ..retry import retry_upstream
from ..transport.cloud import (
    DEFAULT_UPSTREAM_TIMEOUT,
    StreamResult,
    aclose_client,
    forward_anthropic_messages,
    forward_anthropic_messages_stream,
    forward_anthropic_raw,
    forward_anthropic_raw_stream,
    forward_chat_completion_stream,
    forward_openai_json,
    get_client,
)
from .openai_responses import ResponsesSSERestorer, redact_responses_body, restore_responses


def _placeholder_session_tag(body: dict[str, Any], pipeline: OptionBPipeline) -> str | None:
    """Session tag for placeholders: per-request random, or stable per conversation.

    Per-conversation tags keep redacted bytes identical across a session's
    turns — required for upstream prompt caching to see a stable prefix.
    """
    if not pipeline.config.pipeline.placeholder_request_tag:
        return None
    mode = pipeline.config.pipeline.placeholder_tag_mode
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


def _raise_fd_limit(target: int = 65536) -> None:
    """Raise this process's open-file soft limit toward ``target``.

    Each uvicorn worker holds inbound client sockets plus the shared upstream
    pool; macOS ships a 256 soft limit, low enough that a burst of concurrent
    requests can hit EMFILE and stop the worker from calling accept() — at
    which point the gateway sees :7789 as unreachable. Best-effort: a failure
    here is logged, never fatal.
    """
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = target if hard == resource.RLIM_INFINITY else min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            log_event("fd_limit_raised", soft_before=soft, soft_after=new_soft)
    except Exception as exc:  # pragma: no cover - platform/permission dependent
        log_event("fd_limit_raise_failed", error=type(exc).__name__)


def _configure_from_env() -> None:
    """Load config from the environment and wire the pipeline for this worker.

    With ``workers > 1`` uvicorn spawns fresh child processes that re-import
    this module; module globals set in the parent (via ``configure``) do not
    survive the spawn. serve() therefore exports the config location via
    environment variables, and each worker configures itself here — inside its
    own process and event loop — from the lifespan startup hook.
    """
    cfg_path = os.environ.get("LLM_REDACTOR_CONFIG", "llm_redactor.yaml")
    cfg = load_config(Path(cfg_path))
    if port := os.environ.get("LLM_REDACTOR_PORT"):
        cfg.transport.http_port = int(port)
    if upstream := os.environ.get("LLM_REDACTOR_UPSTREAM"):
        cfg.cloud_target.endpoint = upstream
    apply_detection_config(cfg)
    configure(cfg)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Per-worker startup/shutdown.

    Runs once inside each uvicorn worker process: raise the FD ceiling,
    self-configure from the environment when the parent didn't (workers > 1),
    and open/close the shared upstream client alongside the app so its pool is
    warmed before the first request and drained cleanly on shutdown.
    """
    _raise_fd_limit()
    configure_logging()
    if _config is None:
        _configure_from_env()
    get_client()  # warm the shared upstream pool before the first request
    try:
        yield
    finally:
        await aclose_client()


app = FastAPI(title="llm-redactor", version="0.1.0", lifespan=lifespan)

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


def _upstream_status_response(e: httpx.HTTPStatusError) -> JSONResponse:
    """Pass an upstream non-2xx through with its status, body and retry-after.

    A 429 or 529 must reach the agent as itself, or it retries immediately
    instead of backing off (a bare 500 carries no retry semantics).
    """
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
    return JSONResponse(status_code=e.response.status_code, content=err_body, headers=resp_headers)


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

    # Tool-bearing requests.  "redact" (the default) redacts messages, tool
    # results and tool-call arguments like any other request and forwards the
    # tool *schemas* untouched; "refuse" rejects; "bypass" forwards the request
    # unredacted (the old default, which left most agent traffic in the clear).
    if "tools" in body or "functions" in body:
        policy = config.transport.tools_policy
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
                            "transport.tools_policy is 'refuse'. Set it to 'redact' "
                            "(the default) to redact tool-bearing requests."
                        ),
                    },
                },
            )
        if policy == "bypass":
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
    except httpx.HTTPStatusError as e:
        return _upstream_status_response(e)
    except httpx.HTTPError as e:
        return _upstream_transport_error(e, config.cloud_target)

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
    outgoing_messages, scrub, ph_tag = await pipeline.redact_chat_messages(messages)
    stream_detections = scrub.detections

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

    combined_reverse_map = scrub.reverse_map

    log_event(
        "proxy_stream_prepared",
        detections=len(stream_detections),
        placeholder_tag=bool(ph_tag),
    )

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages
    outgoing.pop("extra_body", None)

    # Gate 1: open upstream stream and inspect headers before committing to SSE.
    try:
        upstream = await forward_chat_completion_stream(
            outgoing,
            config.cloud_target,
            upstream_headers=upstream_headers,
        )
    except httpx.HTTPError as e:
        return _upstream_transport_error(e, config.cloud_target)
    if upstream.iterator is None:
        return _plain_upstream_response(upstream)

    # Nothing was redacted: pass the upstream bytes through untouched.
    stream = (
        _restore_openai_sse(upstream.iterator, combined_reverse_map)
        if combined_reverse_map
        else upstream.iterator
    )
    return StreamingResponse(
        _gate_2_openai(stream),
        media_type="text/event-stream",
        headers={"X-LLM-Redactor-Mode": "redacted"},
    )


async def _restore_openai_sse(
    iterator: AsyncIterator[bytes], reverse_map: dict[str, str]
) -> AsyncIterator[bytes]:
    """Restore placeholders in an OpenAI chat-completions SSE stream.

    The stream guarantees neither of the two things the previous version
    assumed.  A network chunk is not a line (lines, and multi-byte UTF-8
    characters, straddle chunks), so bytes are re-assembled into lines first.
    A delta is not a placeholder (models emit ``⟨EMAIL_1⟩`` over several
    deltas), and emitted text cannot be retracted, so each choice gets a
    StreamRestorer that holds back an incomplete placeholder until it closes.
    Streamed tool calls (``delta.tool_calls[i].function.arguments``) are JSON
    text, so each call gets its own restorer that JSON-escapes originals.
    Held text is released at the choice's ``finish_reason`` or before
    ``[DONE]``, never dropped.
    """
    buf = bytearray()
    # (choice, "content") / (choice, "tool", call index) / (choice, "function_call")
    restorers: dict[tuple[Any, ...], StreamRestorer] = {}
    meta: dict[str, Any] = {}  # id/model/... copied onto any synthetic chunk

    def restorer(key: tuple[Any, ...], *, json_text: bool) -> StreamRestorer:
        if key not in restorers:
            escape = json_fragment if json_text else None
            restorers[key] = StreamRestorer(reverse_map, escape=escape)
        return restorers[key]

    def feed(key: tuple[Any, ...], holder: dict[str, Any], field: str, *, json_text: bool) -> bool:
        value = holder.get(field)
        if not isinstance(value, str):
            return False
        new = restorer(key, json_text=json_text).feed(value)
        holder[field] = new
        return new != value

    def flush_into(index: Any, choice: dict[str, Any]) -> bool:
        """Append everything one choice still holds to it (delta, or text)."""
        changed = False
        for key in [k for k in restorers if k[0] == index]:
            held = restorers.pop(key).flush()
            if not held:
                continue
            changed = True
            if key[1] == "text":  # legacy /v1/completions: no delta object
                choice["text"] = (choice.get("text") or "") + held
                continue
            delta = choice.setdefault("delta", {})
            if key[1] == "content":
                delta["content"] = (delta.get("content") or "") + held
                continue
            if key[1] == "tool":
                calls = delta.setdefault("tool_calls", [])
                entry = next(
                    (c for c in calls if isinstance(c, dict) and c.get("index", 0) == key[2]),
                    None,
                )
                if entry is None:
                    entry = {"index": key[2]}
                    calls.append(entry)
                holder = entry.setdefault("function", {})
            else:
                holder = delta.setdefault("function_call", {})
            holder["arguments"] = (holder.get("arguments") or "") + held
        return changed

    def release_all() -> bytes:
        out = bytearray()
        for index in list(dict.fromkeys(k[0] for k in restorers)):
            choice: dict[str, Any] = {"index": index}
            if flush_into(index, choice):
                event = {**meta, "choices": [choice]}
                out += f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode()
        return bytes(out)

    def rewrite(line: bytes) -> bytes:
        if not line.startswith(b"data:"):
            return line
        data = line[5:].strip()
        if data == b"[DONE]":
            return release_all() + line
        try:
            event = json.loads(data)
        except ValueError:
            return line
        if not isinstance(event, dict):
            return line
        meta.update({k: event[k] for k in ("id", "object", "created", "model") if k in event})
        changed = False
        for choice in event.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            if isinstance(choice.get("text"), str) and "delta" not in choice:
                changed |= feed((index, "text"), choice, "text", json_text=False)
                if choice.get("finish_reason") is not None:
                    changed |= flush_into(index, choice)
                continue
            if not isinstance(choice.get("delta"), dict):
                continue
            delta = choice["delta"]
            changed |= feed((index, "content"), delta, "content", json_text=False)
            for call in delta.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict):
                    tool_key = (index, "tool", call.get("index", 0))
                    changed |= feed(tool_key, function, "arguments", json_text=True)
            if isinstance(delta.get("function_call"), dict):
                legacy_key = (index, "function_call")
                changed |= feed(legacy_key, delta["function_call"], "arguments", json_text=True)
            if choice.get("finish_reason") is not None:
                changed |= flush_into(index, choice)
        if not changed:
            return line
        tail = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        return b"data: " + json.dumps(event, ensure_ascii=False).encode() + tail

    async for chunk in iterator:
        buf += chunk
        while (nl := buf.find(b"\n")) != -1:
            line = bytes(buf[: nl + 1])
            del buf[: nl + 1]
            yield rewrite(line)
    if buf:
        yield rewrite(bytes(buf))
    if held := release_all():
        yield held


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
        try:
            upstream = await forward_chat_completion_stream(
                body,
                config.cloud_target,
                upstream_headers=headers,
            )
        except httpx.HTTPError as e:
            return _upstream_transport_error(e, config.cloud_target)
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
        return _upstream_status_response(e)
    except httpx.HTTPError as e:
        # Every transport failure, typed (ReadError etc. used to escape as 500s
        # and ConnectError carried an empty message).
        return _upstream_transport_error(e, config.cloud_target)

    return JSONResponse(content=resp, headers=bypass_headers)


# --------------- Anthropic Messages endpoint ---------------


class _ChunkRestorer(Protocol):
    def feed_chunk(self, chunk: bytes) -> bytes: ...
    def flush(self) -> bytes: ...


async def _restored(
    iterator: AsyncIterator[bytes], restorer: _ChunkRestorer
) -> AsyncIterator[bytes]:
    """Pipe an SSE byte stream through an event-aware placeholder restorer."""
    async for chunk in iterator:
        if out := restorer.feed_chunk(chunk):
            yield out
    if tail := restorer.flush():
        yield tail


async def _handle_anthropic_stream(
    outgoing: dict[str, Any],
    config: Config,
    upstream_headers: dict[str, str],
    combined_reverse_map: dict[str, str],
) -> StreamingResponse | Response:
    """Stream Anthropic SSE chunks from upstream with placeholder restoration.

    This used to pass the stream through untouched, so every streaming client
    (Claude Code always streams) saw raw ``⟨EMAIL_1⟩`` placeholders, and wrote
    them into files whenever the model echoed one inside a tool call.
    """
    # Gate 1: open upstream stream and inspect headers before committing to SSE.
    try:
        upstream = await forward_anthropic_messages_stream(
            outgoing, config.cloud_target, upstream_headers=upstream_headers
        )
    except httpx.HTTPError as e:
        return _upstream_transport_error(e, config.cloud_target)
    if upstream.iterator is None:
        return _plain_upstream_response(upstream)

    stream = (
        _restored(upstream.iterator, SSETextRestorer(combined_reverse_map))
        if combined_reverse_map
        else upstream.iterator
    )
    return StreamingResponse(
        _gate_2_anthropic(stream),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-LLM-Redactor-Mode": "redacted",
        },
    )


async def _redact_anthropic_body(body: dict[str, Any], scrub: RequestScrubber) -> dict[str, Any]:
    """Redact every model-visible string of an unsigned Messages request.

    Scope: ``system`` (string or text blocks) and, in every message, string
    content, ``text`` blocks, ``tool_result`` content, every string inside a
    ``tool_use`` input, and text ``document`` sources.  Only ``text`` blocks
    used to be redacted, and agent traffic keeps most of its secrets in the
    other places: file contents and command output (``cat .env``) come back
    as tool results, and the system prompt carries project instructions.
    ``raw_surgery._is_redactable`` mirrors this scope for signed requests.
    Tool results and inputs are scrubbed as tool content (see
    ``pipeline.tool_content_ner``).
    """

    async def content(value: Any, *, tool: bool = False) -> Any:
        if isinstance(value, str):
            return await scrub.text(value, tool_content=tool)
        if not isinstance(value, list):
            return value
        blocks: list[Any] = []
        for block in value:
            if isinstance(block, dict):
                kind = block.get("type")
                source = block.get("source")
                if kind == "text" and isinstance(block.get("text"), str):
                    block = {**block, "text": await scrub.text(block["text"], tool_content=tool)}
                elif kind == "tool_result" and "content" in block:
                    block = {**block, "content": await content(block["content"], tool=True)}
                elif kind == "tool_use" and "input" in block:
                    block = {**block, "input": await scrub.json_value(block["input"])}
                elif (
                    kind == "document"
                    and isinstance(source, dict)
                    and source.get("type") == "text"
                    and isinstance(source.get("data"), str)
                ):
                    data = await scrub.text(source["data"])
                    block = {**block, "source": {**source, "data": data}}
            blocks.append(block)
        return blocks

    outgoing = dict(body)
    if "system" in body:
        outgoing["system"] = await content(body["system"])
    if isinstance(body.get("messages"), list):
        outgoing["messages"] = [
            {**msg, "content": await content(msg["content"])}
            if isinstance(msg, dict) and "content" in msg
            else msg
            for msg in body["messages"]
        ]
    return outgoing


def _restore_anthropic_content(blocks: list[Any], reverse_map: dict[str, str]) -> None:
    """Restore placeholders in response text blocks and tool-call inputs, in place."""
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            block["text"] = restore(block["text"], reverse_map)
        elif block.get("type") == "tool_use" and "input" in block:
            block["input"] = restore_json(block["input"], reverse_map)


async def _surgical_or_refusal(
    raw: bytes, body: dict[str, Any], pipeline: OptionBPipeline
) -> RawRedaction | JSONResponse:
    """Surgically redact a signed body, or the 422 to return when that fails."""
    gen = PlaceholderGenerator(session_tag=_placeholder_session_tag(body, pipeline))

    async def tool_spans(text: str) -> list[Span]:
        return await pipeline.detect_spans(text, tool_content=True)

    try:
        return await redact_signed_request(
            raw, pipeline.detect_spans, gen, tool_detect_spans=tool_spans
        )
    except SurgeryError as exc:
        pipeline._stats["surgery_failed"] += 1
        log_event("proxy_anthropic_surgery_failed", error=type(exc).__name__)
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "type": "redactor_refused",
                    "reason": "signed_body_unredactable",
                    "message": (
                        "This request carries signed thinking blocks and its raw "
                        "JSON could not be edited safely, so it was not forwarded "
                        "(forwarding it would send it unredacted)."
                    ),
                }
            },
        )


@app.post("/v1/messages", response_model=None)
async def anthropic_messages(request: Request) -> JSONResponse | StreamingResponse | Response:
    """Anthropic Messages API endpoint with redaction.

    Redacts the request (see ``_redact_anthropic_body`` for the scope),
    forwards it to the Anthropic endpoint, and restores placeholders in the
    response, streamed or not.

    If the request carries any ``thinking`` / ``redacted_thinking`` blocks,
    Anthropic validates their signatures against the original JSON bytes —
    any json.loads/dumps round-trip breaks them with a 400.  Those requests
    are redacted surgically on the raw bytes (``raw_surgery``); only when
    there is nothing to redact, or the surgery itself fails, are the inbound
    bytes forwarded unchanged (``X-LLM-Redactor-Mode: signed-passthrough``).
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
    # spliced out at the byte level, leaving signed regions untouched.  With
    # nothing to redact the original bytes go out unchanged; if the surgery
    # itself fails the request is REFUSED (it used to be forwarded raw, i.e.
    # unredacted, exactly when redaction was needed and impossible).
    if isinstance(body, dict) and _body_has_signed_blocks(body):
        pipeline._stats["requests"] += 1
        surgical = await _surgical_or_refusal(raw_body, body, pipeline)
        if isinstance(surgical, JSONResponse):
            return surgical
        if surgical.detections:
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
                return StreamingResponse(
                    _gate_2_anthropic(_restored(upstream.iterator, restorer)),
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

    # Redact every model-visible string (one placeholder tag per upstream request).
    ph_tag = _placeholder_session_tag(body, pipeline)
    scrub = pipeline.scrubber(ph_tag)
    outgoing = await _redact_anthropic_body(body, scrub)
    combined_reverse_map, all_detections = scrub.reverse_map, scrub.detections

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
        return await _handle_anthropic_stream(
            outgoing, config, upstream_headers, combined_reverse_map
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
        return _upstream_status_response(e)
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

    # Restore placeholders in response text and tool-call inputs.
    if combined_reverse_map:
        _restore_anthropic_content(cloud_response["content"], combined_reverse_map)

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

    (The Burp plugin calls ``/v1/redactor/detect-batch`` below instead; it has
    no configurable endpoint field.)
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
        # ONNX inference is CPU-bound: off the event loop, like NER, or every
        # other request on this worker stalls behind it.
        redacted, detections = await asyncio.to_thread(
            _get_image_redactor().redact, source, media_type
        )
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
                "placeholder_tag_mode": cfg.pipeline.placeholder_tag_mode,
                "tool_content_ner": cfg.pipeline.tool_content_ner,
            },
            "transport": {
                "tools_policy": cfg.transport.tools_policy,
                "unknown_path_policy": cfg.transport.unknown_path_policy,
                "mcp_session_cap": cfg.transport.mcp_session_cap,
            },
            "cloud_target": {"endpoint": cfg.cloud_target.endpoint},
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


# --------------- Other OpenAI endpoints ---------------

_HEADERS_NOT_FORWARDED = frozenset(
    {
        "host",
        "transfer-encoding",
        "connection",
        "content-length",
        "content-encoding",
        "accept-encoding",
    }
)


def _upstream_headers(request: Request) -> dict[str, str]:
    """Inbound headers minus hop-by-hop ones (and accept-encoding, see chat_completions)."""
    return {k: v for k, v in request.headers.items() if k.lower() not in _HEADERS_NOT_FORWARDED}


async def _json_object(request: Request) -> dict[str, Any] | JSONResponse:
    raw = await request.body()
    try:
        body = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"type": "invalid_request_error", "message": str(e)}},
        )
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={"error": {"type": "invalid_request_error", "message": "expected an object"}},
        )
    return body


def _strict_refusal(pipeline: OptionBPipeline, detections: list[Span]) -> JSONResponse | None:
    if not pipeline.config.pipeline.opt_b_redact.strict:
        return None
    low_conf = [s for s in detections if s.confidence < 0.5]
    if not low_conf:
        return None
    pipeline._stats["refusals"] += 1
    return _refusal_response(RefusalError(reason="low_confidence_detection", spans=low_conf))


async def _redacted_openai_call(
    request: Request,
    path: str,
    outgoing: dict[str, Any],
    scrub: RequestScrubber,
    restore_body: Callable[[dict[str, Any], dict[str, str]], None] | None,
    make_stream_restorer: Callable[[AsyncIterator[bytes]], AsyncIterator[bytes]] | None,
) -> Response:
    """Forward an already-redacted OpenAI request, restoring the response."""
    pipeline, config = _get_pipeline(), _get_config()
    pipeline._stats["requests"] += 1
    pipeline._stats["detections"] += len(scrub.detections)
    if refusal := _strict_refusal(pipeline, scrub.detections):
        return refusal
    headers = _upstream_headers(request)
    if outgoing.get("stream") and make_stream_restorer is not None:
        try:
            upstream = await forward_chat_completion_stream(
                outgoing, config.cloud_target, upstream_headers=headers, path=path
            )
        except httpx.HTTPError as e:
            return _upstream_transport_error(e, config.cloud_target)
        if upstream.iterator is None:
            return _plain_upstream_response(upstream)
        stream = make_stream_restorer(upstream.iterator) if scrub.reverse_map else upstream.iterator
        gate = _gate_2_anthropic if path == "responses" else _gate_2_openai
        return StreamingResponse(
            gate(stream),
            media_type="text/event-stream",
            headers={"X-LLM-Redactor-Mode": "redacted"},
        )
    try:
        response = await forward_openai_json(
            path, outgoing, config.cloud_target, upstream_headers=headers
        )
    except httpx.HTTPStatusError as e:
        return _upstream_status_response(e)
    except httpx.HTTPError as e:
        return _upstream_transport_error(e, config.cloud_target)
    if restore_body is not None and scrub.reverse_map:
        restore_body(response, scrub.reverse_map)
    return JSONResponse(content=response, headers={"X-LLM-Redactor-Mode": "redacted"})


@app.post("/v1/responses", response_model=None)
async def openai_responses(request: Request) -> Response:
    """OpenAI Responses API (Codex and newer OpenAI agents), redacted.

    See transport/openai_responses.py for the scope.  This endpoint used to
    fall through to the raw catch-all, i.e. upstream unredacted.
    """
    body = await _json_object(request)
    if isinstance(body, JSONResponse):
        return body
    pipeline = _get_pipeline()
    scrub = pipeline.scrubber(pipeline.request_placeholder_tag())
    outgoing = await redact_responses_body(body, scrub)
    return await _redacted_openai_call(
        request,
        "responses",
        outgoing,
        scrub,
        restore_responses,
        lambda it: _restored(it, ResponsesSSERestorer(scrub.reverse_map)),
    )


@app.post("/v1/completions", response_model=None)
async def openai_completions(request: Request) -> Response:
    """Legacy completions: ``prompt`` / ``suffix`` redacted, ``choices[].text`` restored."""
    body = await _json_object(request)
    if isinstance(body, JSONResponse):
        return body
    pipeline = _get_pipeline()
    scrub = pipeline.scrubber(pipeline.request_placeholder_tag())
    outgoing = dict(body)
    prompt = body.get("prompt")
    if isinstance(prompt, str):
        outgoing["prompt"] = await scrub.text(prompt)
    elif isinstance(prompt, list):  # strings, or token arrays (left alone)
        outgoing["prompt"] = [await scrub.text(p) if isinstance(p, str) else p for p in prompt]
    if isinstance(body.get("suffix"), str):
        outgoing["suffix"] = await scrub.text(body["suffix"])

    def restore_choices(response: dict[str, Any], reverse_map: dict[str, str]) -> None:
        for choice in response.get("choices") or []:
            if isinstance(choice, dict) and isinstance(choice.get("text"), str):
                choice["text"] = restore(choice["text"], reverse_map)

    return await _redacted_openai_call(
        request,
        "completions",
        outgoing,
        scrub,
        restore_choices,
        lambda it: _restore_openai_sse(it, scrub.reverse_map),
    )


@app.post("/v1/embeddings", response_model=None)
async def openai_embeddings(request: Request) -> Response:
    """Embeddings: the ``input`` strings are redacted before they are embedded.

    Vectors of redacted text are what privacy requires here, but note the
    semantic cost: ``⟨PERSON_1⟩`` is numbered per request, so the same name
    embedded in two requests may get different placeholders.
    """
    body = await _json_object(request)
    if isinstance(body, JSONResponse):
        return body
    pipeline = _get_pipeline()
    scrub = pipeline.scrubber(None)
    outgoing = dict(body)
    value = body.get("input")
    if isinstance(value, str):
        outgoing["input"] = await scrub.text(value)
    elif isinstance(value, list):  # strings, or token arrays (left alone)
        outgoing["input"] = [await scrub.text(v) if isinstance(v, str) else v for v in value]
    return await _redacted_openai_call(request, "embeddings", outgoing, scrub, None, None)


@app.post("/v1/messages/count_tokens", response_model=None)
async def anthropic_count_tokens(request: Request) -> Response:
    """Token counting, redacted exactly like ``/v1/messages``.

    The body is the same conversation the next ``/v1/messages`` call sends, so
    the old raw passthrough leaked everything that call redacts.  Counting the
    redacted body is also the *right* count: it is what the model receives.
    With nothing to redact, the inbound bytes are forwarded untouched.
    """
    raw = await request.body()
    try:
        body: Any = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        return JSONResponse(
            status_code=400,
            content={"error": {"type": "invalid_request_error", "message": str(e)}},
        )
    pipeline = _get_pipeline()
    forward = raw
    if isinstance(body, dict):
        if _body_has_signed_blocks(body):
            surgical = await _surgical_or_refusal(raw, body, pipeline)
            if isinstance(surgical, JSONResponse):
                return surgical
            forward = surgical.new_raw
        else:
            scrub = pipeline.scrubber(_placeholder_session_tag(body, pipeline))
            outgoing = await _redact_anthropic_body(body, scrub)
            if scrub.detections:
                forward = json.dumps(outgoing, ensure_ascii=False).encode("utf-8")
    return await _forward_raw(request, "v1/messages/count_tokens", forward)


# --------------- Catch-all raw passthrough ---------------


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def raw_passthrough(request: Request, path: str) -> Response:
    """Catch-all for endpoints without a dedicated route (models, batches, …).

    Registered LAST so every explicit route above wins.  Forwards the inbound
    bytes RAW to the upstream — no redaction, no JSON round-trip.  NOTE: that
    means any content-bearing endpoint without a route of its own here (files,
    batches, assistants, or any path under a base URL missing its ``/v1``)
    would reach the cloud unredacted.  So requests that carry a body are
    refused unless ``transport.unknown_path_policy: forward``; bodiless ones
    (``GET /v1/models``) are forwarded, marked
    ``X-LLM-Redactor-Mode: raw-passthrough``.
    """
    body = await request.body()
    if body and _get_config().transport.unknown_path_policy == "refuse":
        log_event("proxy_unknown_path_refused", method=request.method)
        return _unknown_path_refusal(path)
    return await _forward_raw(request, path, body)


_ROUTED = ("chat/completions", "completions", "embeddings", "responses", "messages")


def _unknown_path_refusal(path: str) -> JSONResponse:
    message = (
        f"llm-redactor has no redaction route for /{path}, so the request was not "
        "forwarded (set transport.unknown_path_policy: forward to send such "
        "requests raw, unredacted)."
    )
    if path.rstrip("/").endswith(_ROUTED) and not path.startswith("v1/"):
        message += " This looks like a client base URL missing its /v1."
    return JSONResponse(
        status_code=422,
        content={
            "error": {"type": "redactor_refused", "reason": "unknown_path", "message": message}
        },
    )


async def _forward_raw(request: Request, path: str, content: bytes) -> Response:
    """Forward ``content`` to ``<endpoint>/<path>`` with the inbound method and query.

    Header recipe mirrors ``forward_anthropic_raw`` (cloud.py): forwarded
    headers minus hop-by-hop, then content-type + anthropic-version defaults,
    and the env API key only when the client sent neither ``x-api-key`` nor
    ``authorization``.
    """
    config = _get_config()
    mode = "redacted" if path == "v1/messages/count_tokens" else "raw-passthrough"

    _skip_hop = frozenset(
        {"host", "transfer-encoding", "connection", "content-length", "content-encoding"}
    )
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _skip_hop}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    api_key = os.environ.get(config.cloud_target.api_key_env, "")
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key

    # cloud_target.endpoint already carries the API-version segment (e.g.
    # ".../api.openai.com/v1") while FastAPI's {path:path} includes the
    # leading "v1" — drop that segment so we never build ".../v1/v1/…".
    parts = path.split("/")
    if parts and parts[0] == "v1":
        parts = parts[1:]
    url = f"{config.cloud_target.endpoint.rstrip('/')}/{('/'.join(parts))}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    try:
        # The shared, bounded pool (cloud.get_client): a fresh AsyncClient per
        # request is the FD-exhaustion pattern cloud.py documents and removed
        # everywhere else.  Pre-commit: the full body is read before the
        # response is built, so a transient transport failure may be re-sent;
        # the same bytes go out again and redaction is never re-run.
        client = get_client()
        resp = await retry_upstream(
            lambda: client.request(
                request.method,
                url,
                content=content,
                headers=headers,
                timeout=DEFAULT_UPSTREAM_TIMEOUT,
            ),
            operation="raw passthrough",
        )
    except httpx.HTTPError as e:
        return _upstream_transport_error(e, config.cloud_target)

    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _HOP_BY_HOP}
    out_headers["X-LLM-Redactor-Mode"] = mode
    return Response(content=resp.content, status_code=resp.status_code, headers=out_headers)
