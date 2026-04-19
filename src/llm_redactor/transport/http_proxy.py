"""FastAPI-based HTTP proxy — OpenAI-compatible + Anthropic Messages API.

Supports both non-streaming and streaming (SSE) requests.  For streaming,
the proxy buffers content deltas, restores placeholders in the accumulated
text, and re-emits corrected SSE chunks.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..config import Config
from ..detect.types import Span
from ..observability import log_event
from ..pipeline.option_b import OptionBPipeline, RefusalError
from ..redact.placeholder import redact
from ..redact.restore import restore
from ..transport.cloud import (
    forward_anthropic_messages,
    forward_chat_completion_stream,
)

app = FastAPI(title="llm-redactor", version="0.1.0")

# Initialized at startup via configure().
_pipeline: OptionBPipeline | None = None
_config: Config | None = None


def configure(config: Config, *, use_ner: bool = True) -> FastAPI:
    """Wire the pipeline into the app. Call before serving."""
    global _pipeline, _config
    _pipeline = OptionBPipeline(config=config, use_ner=use_ner)
    _config = config
    return app


def _get_pipeline() -> OptionBPipeline:
    if _pipeline is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _pipeline


def _get_config() -> Config:
    if _config is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _config


# --------------- OpenAI-compatible endpoints ---------------


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(request: Request) -> JSONResponse | StreamingResponse:
    """OpenAI-compatible chat completion endpoint with redaction.

    Supports both ``stream: false`` (default) and ``stream: true``.
    """
    body: dict[str, Any] = await request.json()
    pipeline = _get_pipeline()
    config = _get_config()

    # Forward all headers from the incoming request (minus hop-by-hop).
    _skip = frozenset(
        {"host", "transfer-encoding", "connection", "content-length", "content-encoding"}
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
            body, pipeline, config, upstream_headers, strict=effective_strict,
        )

    try:
        result = await pipeline.run(
            body, upstream_headers=upstream_headers, strict=effective_strict,
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
) -> StreamingResponse | JSONResponse:
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

        async for chunk in forward_chat_completion_stream(
            outgoing,
            config.cloud_target,
            upstream_headers=upstream_headers,
        ):
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
        generate(),
        media_type="text/event-stream",
        headers={"X-LLM-Redactor-Mode": "redacted"},
    )


async def _forward_openai_transparent(
    body: dict[str, Any],
    config: Config,
    headers: dict[str, str],
) -> StreamingResponse | JSONResponse:
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

        async def generate() -> AsyncIterator[bytes]:
            async for chunk in forward_chat_completion_stream(
                body,
                config.cloud_target,
                upstream_headers=headers,
            ):
                yield chunk

        return StreamingResponse(
            generate(),
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
            err_body = {"error": e.response.text[:500]}
        return JSONResponse(status_code=e.response.status_code, content=err_body)
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return JSONResponse(
            status_code=502,
            content={"error": {"type": "upstream_error", "message": str(e)}},
        )

    return JSONResponse(content=resp, headers=bypass_headers)


# --------------- Anthropic Messages endpoint ---------------


@app.post("/v1/messages")
async def anthropic_messages(request: Request) -> JSONResponse:
    """Anthropic Messages API endpoint with redaction.

    Redacts content blocks in the request, forwards to the Anthropic
    endpoint, and restores placeholders in the response.
    """
    body: dict[str, Any] = await request.json()
    pipeline = _get_pipeline()
    config = _get_config()

    # Redact content in each message (one placeholder tag per upstream request).
    messages = body.get("messages", [])
    combined_reverse_map: dict[str, str] = {}
    all_detections: list[Span] = []
    ph_tag = pipeline.request_placeholder_tag()

    outgoing_messages = []
    for msg in messages:
        content = msg.get("content", "")
        # Anthropic supports string content or list of content blocks.
        if isinstance(content, str):
            spans = await pipeline.detect_spans(content)
            all_detections.extend(spans)
            if spans:
                result = redact(content, spans, session_tag=ph_tag)
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
                        result = redact(block["text"], spans, session_tag=ph_tag)
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
            return _refusal_response(
                RefusalError(reason="low_confidence_detection", spans=low_conf)
            )

    log_event(
        "proxy_anthropic_prepared",
        detections=len(all_detections),
        placeholder_tag=bool(ph_tag),
    )

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages
    # Ensure stream is false (streaming Anthropic not implemented here).
    outgoing["stream"] = False

    # Forward all headers from the incoming request (minus hop-by-hop).
    _skip = frozenset(
        {"host", "transfer-encoding", "connection", "content-length", "content-encoding"}
    )
    upstream_headers = {k: v for k, v in request.headers.items() if k.lower() not in _skip}

    try:
        cloud_response = await forward_anthropic_messages(
            outgoing, config.cloud_target, upstream_headers=upstream_headers
        )
    except httpx.HTTPStatusError as e:
        # Pass through the upstream status code and body instead of masking as 502.
        try:
            err_body = e.response.json()
        except Exception:
            err_body = {"error": e.response.text[:500]}
        return JSONResponse(status_code=e.response.status_code, content=err_body)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})

    # Restore placeholders in response content blocks.
    if combined_reverse_map and "content" in cloud_response:
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
                "placeholder_request_tag": cfg.pipeline.placeholder_request_tag,
            },
            "transport": {
                "tools_policy": cfg.transport.tools_policy,
                "mcp_session_cap": cfg.transport.mcp_session_cap,
            },
            "cloud_target": {
                "backend": cfg.cloud_target.backend,
                "endpoint": cfg.cloud_target.endpoint,
            },
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
