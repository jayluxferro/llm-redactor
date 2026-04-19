"""MCP session store behaviour."""

from __future__ import annotations

import llm_redactor.transport.mcp_server as mcp_server
from llm_redactor.config import Config


def test_mcp_session_eviction_respects_cap() -> None:
    mcp_server._sessions.clear()
    cfg = Config()
    cfg.transport.mcp_session_cap = 2
    mcp_server._config = cfg
    mcp_server._remember_session("session-a", {"x": "y"})
    mcp_server._remember_session("session-b", {"p": "q"})
    mcp_server._remember_session("session-c", {"r": "s"})
    assert "session-a" not in mcp_server._sessions
    assert "session-c" in mcp_server._sessions
    assert len(mcp_server._sessions) == 2
