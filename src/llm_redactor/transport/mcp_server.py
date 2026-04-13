"""MCP stdio server for privacy-preserving LLM requests.

Tools:
  llm.chat        — Drop-in replacement for LLM calls. Scrubs sensitive
                    content, forwards to cloud, restores placeholders,
                    returns the clean response. Agent uses this instead
                    of calling the LLM directly.
  redact.scrub    — Detect and redact sensitive content. Returns redacted
                    text + session_id for later restoration.
  redact.restore  — Given a response and session_id, restore placeholders
                    back to original values.
  redact.detect   — Dry-run: detect sensitive spans without redacting.
  redact.stats    — Aggregate counters since process start.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ..config import Config, load_config
from ..detect.orchestrator import detect_all
from ..redact.placeholder import redact
from ..redact.restore import restore

server = Server("llm-redactor")
_config: Config | None = None
_stats: dict[str, int] = {"requests": 0, "detections": 0, "restores": 0, "llm_calls": 0}

# In-memory reverse map store, keyed by session_id.
# Each scrub creates a session; restore consumes it.
_sessions: dict[str, dict[str, str]] = {}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="llm.chat",
            description=(
                "Send a message to an LLM with automatic privacy protection. "
                "Detects and redacts PII/secrets before sending, then restores "
                "placeholders in the response. Use this instead of calling the "
                "LLM directly when the content may contain sensitive data."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "messages": {
                        "type": "array",
                        "description": "Chat messages in OpenAI format.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "role": {"type": "string", "enum": ["system", "user", "assistant"]},
                                "content": {"type": "string"},
                            },
                            "required": ["role", "content"],
                        },
                    },
                    "model": {
                        "type": "string",
                        "description": "Model name (e.g. gpt-4o, claude-sonnet-4-20250514). Optional — uses server default if omitted.",
                    },
                    "max_tokens": {
                        "type": "integer",
                        "description": "Maximum tokens in response. Default 1024.",
                    },
                },
                "required": ["messages"],
            },
        ),
        Tool(
            name="redact.scrub",
            description=(
                "Detect and redact sensitive content (PII, secrets, org names) "
                "from text. Returns the redacted text and a session_id. "
                "Pass the session_id to redact.restore after getting the LLM response."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to scrub before sending to an LLM.",
                    },
                    "use_ner": {
                        "type": "boolean",
                        "description": "Enable Presidio NER for better person/org detection (slower). Default true.",
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="redact.restore",
            description=(
                "Restore placeholders in an LLM response back to original values. "
                "Requires the session_id from a prior redact.scrub call."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The LLM response containing placeholders to restore.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "The session_id returned by redact.scrub.",
                    },
                },
                "required": ["text", "session_id"],
            },
        ),
        Tool(
            name="redact.detect",
            description="Dry-run: detect sensitive spans without redacting. Returns span details.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to scan for sensitive content.",
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="redact.stats",
            description="Aggregate counters since process start.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "llm.chat":
        return await _handle_llm_chat(arguments)
    elif name == "redact.scrub":
        return _handle_scrub(arguments)
    elif name == "redact.restore":
        return _handle_restore(arguments)
    elif name == "redact.detect":
        return _handle_detect(arguments)
    elif name == "redact.stats":
        return [TextContent(type="text", text=json.dumps(_stats))]
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]


async def _handle_llm_chat(arguments: dict[str, Any]) -> list[TextContent]:
    """Scrub → forward to LLM → restore. One-shot privacy-preserving LLM call."""
    global _config
    if _config is None:
        _config = load_config()

    _stats["llm_calls"] += 1
    _stats["requests"] += 1

    messages = arguments.get("messages", [])
    model = arguments.get("model", "")
    max_tokens = arguments.get("max_tokens", 1024)

    # Step 1: Detect and redact each message.
    combined_reverse_map: dict[str, str] = {}
    redacted_messages = []
    total_detections = 0

    for msg in messages:
        content = msg.get("content", "")
        if not isinstance(content, str) or not content:
            redacted_messages.append(msg)
            continue

        spans = detect_all(content, use_ner=True)
        total_detections += len(spans)

        if spans:
            result = redact(content, spans)
            combined_reverse_map.update(result.reverse_map)
            redacted_messages.append({**msg, "content": result.redacted_text})
        else:
            redacted_messages.append(msg)

    _stats["detections"] += total_detections

    # Step 2: Forward to cloud LLM.
    endpoint = _config.cloud_target.endpoint
    api_key = os.environ.get(_config.cloud_target.api_key_env, "")

    body: dict[str, Any] = {
        "messages": redacted_messages,
        "max_tokens": max_tokens,
    }
    if model:
        body["model"] = model

    url = f"{endpoint.rstrip('/')}/chat/completions"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            cloud_response = resp.json()
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({
            "error": f"LLM call failed: {e}",
            "redacted_messages": redacted_messages,
            "detections": total_detections,
        }))]

    # Step 3: Restore placeholders in response.
    response_text = ""
    if "choices" in cloud_response and cloud_response["choices"]:
        response_text = cloud_response["choices"][0].get("message", {}).get("content", "")

    if combined_reverse_map and response_text:
        restored_text = restore(response_text, combined_reverse_map)
        _stats["restores"] += 1
    else:
        restored_text = response_text

    return [TextContent(type="text", text=json.dumps({
        "response": restored_text,
        "model": cloud_response.get("model", model),
        "detections": total_detections,
        "placeholders_restored": len(combined_reverse_map) if combined_reverse_map else 0,
        "usage": cloud_response.get("usage"),
    }))]


def _handle_scrub(arguments: dict[str, Any]) -> list[TextContent]:
    _stats["requests"] += 1

    text = arguments.get("text", "")
    use_ner = arguments.get("use_ner", True)

    spans = detect_all(text, use_ner=use_ner)
    _stats["detections"] += len(spans)

    if not spans:
        return [TextContent(type="text", text=json.dumps({
            "redacted_text": text,
            "session_id": None,
            "detections": 0,
            "message": "No sensitive content detected. Safe to send as-is.",
        }))]

    result = redact(text, spans)

    session_id = str(uuid.uuid4())
    _sessions[session_id] = result.reverse_map

    return [TextContent(type="text", text=json.dumps({
        "redacted_text": result.redacted_text,
        "session_id": session_id,
        "detections": len(spans),
        "detected_kinds": list({s.kind for s in spans}),
        "message": f"Redacted {len(spans)} sensitive span(s). Use this redacted_text in your LLM call, then pass the response to redact.restore with this session_id.",
    }))]


def _handle_restore(arguments: dict[str, Any]) -> list[TextContent]:
    text = arguments.get("text", "")
    session_id = arguments.get("session_id", "")

    if not session_id or session_id not in _sessions:
        return [TextContent(type="text", text=json.dumps({
            "restored_text": text,
            "error": "Unknown or expired session_id. Returning text unchanged.",
        }))]

    reverse_map = _sessions.pop(session_id)  # consume the session
    _stats["restores"] += 1

    restored_text = restore(text, reverse_map)

    return [TextContent(type="text", text=json.dumps({
        "restored_text": restored_text,
        "placeholders_restored": len(reverse_map),
    }))]


def _handle_detect(arguments: dict[str, Any]) -> list[TextContent]:
    text = arguments.get("text", "")
    spans = detect_all(text, use_ner=True)
    return [TextContent(type="text", text=json.dumps({
        "spans": [
            {
                "start": s.start,
                "end": s.end,
                "kind": s.kind,
                "confidence": s.confidence,
                "text": s.text,
                "source": s.source,
            }
            for s in spans
        ],
    }))]


async def run_mcp(config: Config | None = None) -> None:
    """Start the MCP stdio server."""
    global _config
    if config:
        _config = config

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
