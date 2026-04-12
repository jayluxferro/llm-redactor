"""MCP stdio server: redact.transform, redact.detect, redact.stats."""

from __future__ import annotations

from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ..config import Config
from ..detect.orchestrator import detect_all
from ..pipeline.option_b import OptionBPipeline, RefusalError

server = Server("llm-redactor")
_pipeline: OptionBPipeline | None = None
_config: Config | None = None


def _get_pipeline() -> OptionBPipeline:
    global _pipeline, _config
    if _pipeline is None:
        _config = _config or Config()
        _pipeline = OptionBPipeline(config=_config)
    return _pipeline


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="redact.transform",
            description=(
                "Run the full privacy pipeline: detect sensitive spans, "
                "redact, forward to the cloud target, and restore the response."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "messages": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "role": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["role", "content"],
                        },
                    },
                    "model": {"type": "string"},
                    "strict": {"type": "boolean"},
                },
                "required": ["messages"],
            },
        ),
        Tool(
            name="redact.detect",
            description="Dry-run: detect sensitive spans without sending anything.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
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
    import json

    if name == "redact.transform":
        return await _handle_transform(arguments)
    elif name == "redact.detect":
        return await _handle_detect(arguments)
    elif name == "redact.stats":
        return await _handle_stats()
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]


async def _handle_transform(arguments: dict[str, Any]) -> list[TextContent]:
    import json

    pipeline = _get_pipeline()
    body: dict[str, Any] = {
        "messages": arguments["messages"],
    }
    if "model" in arguments:
        body["model"] = arguments["model"]
    if "strict" in arguments:
        pipeline.config.pipeline.opt_b_redact.strict = bool(arguments["strict"])

    try:
        result = await pipeline.run(body)
    except RefusalError as e:
        return [TextContent(type="text", text=json.dumps({
            "error": "refused",
            "reason": e.reason,
            "detected_spans": [
                {"kind": s.kind, "confidence": s.confidence}
                for s in e.spans
            ],
        }))]

    return [TextContent(type="text", text=json.dumps({
        "response": result.response,
        "detections": [
            {"kind": s.kind, "count": 1} for s in result.detections
        ],
        "options_applied": result.options_applied,
        "leak_audit": result.leak_audit,
    }))]


async def _handle_detect(arguments: dict[str, Any]) -> list[TextContent]:
    import json

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


async def _handle_stats() -> list[TextContent]:
    import json

    pipeline = _get_pipeline()
    return [TextContent(type="text", text=json.dumps(pipeline.stats))]


async def run_mcp(config: Config | None = None) -> None:
    """Start the MCP stdio server."""
    global _config
    if config:
        _config = config

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
