"""FastAPI-based HTTP proxy — OpenAI-compatible + Anthropic Messages API.

Supports both non-streaming and streaming (SSE) requests.  For streaming,
the proxy buffers content deltas, restores placeholders in the accumulated
text, and re-emits corrected SSE chunks.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..config import Config
from ..detect.orchestrator import detect_all
from ..detect.types import Span
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

    # Allow per-request overrides via extra_body.redactor.
    extra = body.get("extra_body", {}).get("redactor", {})
    strict_override = extra.get("strict")
    if strict_override is not None:
        pipeline.config.pipeline.opt_b_redact.strict = bool(strict_override)

    is_stream = body.get("stream", False)

    if is_stream:
        return await _handle_openai_stream(body, pipeline, config)

    try:
        result = await pipeline.run(body)
    except RefusalError as e:
        return _refusal_response(e)

    # Build the response with redactor metadata.
    response_body = result.response
    response_body["redactor"] = {
        "options_applied": result.options_applied,
        "detections": _summarize_detections(result.detections),
        "leak_audit": result.leak_audit,
    }

    return JSONResponse(content=response_body)


async def _handle_openai_stream(
    body: dict[str, Any],
    pipeline: OptionBPipeline,
    config: Config,
) -> StreamingResponse:
    """Redact the request, stream from cloud, restore placeholders in deltas."""
    # Detect and redact messages.
    messages = body.get("messages", [])
    combined_reverse_map: dict[str, str] = {}

    outgoing_messages = list(messages)
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if not isinstance(content, str) or not content:
            continue
        spans = detect_all(content, use_ner=pipeline.use_ner)
        if spans:
            result = redact(content, spans)
            outgoing_messages[i] = {**msg, "content": result.redacted_text}
            combined_reverse_map.update(result.reverse_map)

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages
    outgoing.pop("extra_body", None)

    async def generate():
        accumulated = ""
        async for chunk in forward_chat_completion_stream(outgoing, config.cloud_target):
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
                        delta = choice.get("delta", {})
                        if "content" in delta and delta["content"] and combined_reverse_map:
                            accumulated += delta["content"]
                            restored = restore(accumulated, combined_reverse_map)
                            # Emit the full restored content as delta.
                            delta["content"] = restored
                            accumulated = ""  # Reset after restore.
                    yield f"data: {json.dumps(event)}\n\n".encode()
                except json.JSONDecodeError:
                    yield (line + "\n").encode()

    return StreamingResponse(generate(), media_type="text/event-stream")


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

    # Redact content in each message.
    messages = body.get("messages", [])
    combined_reverse_map: dict[str, str] = {}
    all_detections: list[Span] = []

    outgoing_messages = []
    for msg in messages:
        content = msg.get("content", "")
        # Anthropic supports string content or list of content blocks.
        if isinstance(content, str):
            spans = detect_all(content, use_ner=pipeline.use_ner)
            all_detections.extend(spans)
            if spans:
                result = redact(content, spans)
                combined_reverse_map.update(result.reverse_map)
                outgoing_messages.append({**msg, "content": result.redacted_text})
            else:
                outgoing_messages.append(msg)
        elif isinstance(content, list):
            # List of content blocks [{type: "text", text: "..."}].
            new_blocks = []
            for block in content:
                if block.get("type") == "text" and "text" in block:
                    spans = detect_all(block["text"], use_ner=pipeline.use_ner)
                    all_detections.extend(spans)
                    if spans:
                        result = redact(block["text"], spans)
                        combined_reverse_map.update(result.reverse_map)
                        new_blocks.append({**block, "text": result.redacted_text})
                    else:
                        new_blocks.append(block)
                else:
                    new_blocks.append(block)
            outgoing_messages.append({**msg, "content": new_blocks})
        else:
            outgoing_messages.append(msg)

    outgoing = dict(body)
    outgoing["messages"] = outgoing_messages
    # Ensure stream is false (streaming Anthropic not implemented here).
    outgoing["stream"] = False

    # Forward all headers from the incoming request (minus hop-by-hop).
    _skip = frozenset({"host", "transfer-encoding", "connection", "content-length", "content-encoding", "anthropic-beta"})
    upstream_headers = {k: v for k, v in request.headers.items() if k.lower() not in _skip}

    try:
        cloud_response = await forward_anthropic_messages(
            outgoing, config.cloud_target, upstream_headers=upstream_headers
        )
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

    return JSONResponse(content=cloud_response)


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
    return JSONResponse(content={
        "pipeline": {
            "opt_b_redact": {
                "enabled": cfg.pipeline.opt_b_redact.enabled,
                "strict": cfg.pipeline.opt_b_redact.strict,
            },
        },
        "cloud_target": {
            "backend": cfg.cloud_target.backend,
            "endpoint": cfg.cloud_target.endpoint,
        },
    })


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
