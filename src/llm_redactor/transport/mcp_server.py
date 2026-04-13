"""MCP stdio server for privacy-preserving LLM requests.

Tools:
  redact.scrub    — Detect and redact sensitive content. Returns redacted
                    text + session_id for later restoration.
  redact.restore  — Given a response and session_id, restore placeholders
                    back to original values.
  redact.detect   — Dry-run: detect sensitive spans without redacting.
  redact.stats    — Aggregate counters since process start.

Designed for MCP-mode where the agent handles its own cloud calls.
The redactor never contacts a cloud LLM — it just scrubs content.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ..config import Config
from ..detect.orchestrator import detect_all
from ..redact.placeholder import redact
from ..redact.restore import restore

server = Server("llm-redactor")
_config: Config | None = None
_stats: dict[str, int] = {"requests": 0, "detections": 0, "restores": 0}

# In-memory reverse map store, keyed by session_id.
# Each scrub creates a session; restore consumes it.
_sessions: dict[str, dict[str, str]] = {}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
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
    if name == "redact.scrub":
        return _handle_scrub(arguments)
    elif name == "redact.restore":
        return _handle_restore(arguments)
    elif name == "redact.detect":
        return _handle_detect(arguments)
    elif name == "redact.stats":
        return [TextContent(type="text", text=json.dumps(_stats))]
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]


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
