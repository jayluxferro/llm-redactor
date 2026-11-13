"""The MCP server end to end over stdio, driven by the SDK's own client.

The other MCP tests call the handlers directly, so nothing exercised the
`mcp` package itself; an SDK upgrade that breaks `Server` or `stdio_server`
(the 1.x low-level API that transport/mcp_server.py is built on) now fails
here instead of in a user's agent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_stdio_handshake_lists_tools_and_round_trips(tmp_path: Path) -> None:
    config = tmp_path / "llm_redactor.yaml"
    config.write_text("version: 1\n")
    server = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from llm_redactor.cli import app; app()", "mcp", "--config", str(config)],
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {tool.name for tool in (await session.list_tools()).tools}
        assert {"redact.scrub", "redact.restore", "redact.detect"} <= tools

        scrubbed = await session.call_tool(
            "redact.scrub", {"text": "mail alice@example.com today", "use_ner": False}
        )
        payload = json.loads(scrubbed.content[0].text)  # type: ignore[union-attr]
        assert "alice@example.com" not in payload["redacted_text"]

        placeholder = payload["redacted_text"].split()[1]
        restored = await session.call_tool(
            "redact.restore",
            {"session_id": payload["session_id"], "text": f"wrote to {placeholder}"},
        )
        assert "alice@example.com" in restored.content[0].text  # type: ignore[union-attr]
