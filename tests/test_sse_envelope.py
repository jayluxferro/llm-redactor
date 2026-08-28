"""SSE envelope regression tests (spec §5).

Validates Gates 1 and 2 across the llm-redactor streaming paths:
- Gate 1: never commit to SSE before upstream proves it has one.
- Gate 2: never let a committed stream end with zero complete frames.

All upstreams are mocked; no network traffic leaves the test process.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.redact.placeholder import PREFIX as PH_PREFIX
from llm_redactor.redact.placeholder import SUFFIX as PH_SUFFIX
from llm_redactor.transport.cloud import StreamResult
from llm_redactor.transport.http_proxy import app, configure


def _client(endpoint: str = "http://test-cloud.invalid/v1") -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    cfg.cloud_target.endpoint = endpoint
    configure(cfg, use_ner=False)
    return TestClient(app)


def _terminal_error_openai(
    exc_type: str = "RemoteProtocolError", message: str = "RemoteProtocolError: peer closed"
) -> bytes:
    err = json.dumps({"error": {"type": exc_type, "message": message}})
    return f"data: {err}\n\n".encode() + b"data: [DONE]\n\n"


def _terminal_error_anthropic(
    exc_type: str = "RemoteProtocolError", message: str = "RemoteProtocolError: peer closed"
) -> bytes:
    err = json.dumps({"error": {"type": exc_type, "message": message}})
    return f"event: error\ndata: {err}\n\n".encode()


def _sse_events(*events: dict[str, Any]) -> bytes:
    out = bytearray()
    for ev in events:
        out += f"data: {json.dumps(ev)}\n\n".encode()
    out += b"data: [DONE]\n\n"
    return bytes(out)


class _AsyncStream(httpx.AsyncByteStream):
    """Async byte stream for pytest_httpx ``stream=`` registrations.

    pytest_httpx passes ``stream`` straight into ``httpx.Response``; a plain
    list of bytes becomes a SYNC IteratorByteStream, which trips the
    ``AsyncByteStream`` assertion in ``AsyncClient.send(stream=True)``.
    """

    def __init__(self, parts: list[bytes]) -> None:
        self._parts = parts

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for part in self._parts:
            yield part

    async def aclose(self) -> None:
        pass


# -----------------------------------------------------------------------------
# OpenAI /v1/chat/completions
# -----------------------------------------------------------------------------


def test_openai_stream_401_propagation(httpx_mock: Any) -> None:
    """A. Upstream 401 on a streaming request must return 401 application/json."""
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/chat/completions",
        status_code=401,
        json={"error": {"type": "invalid_api_key", "message": "bad key"}},
        headers={"content-type": "application/json"},
    )
    c = _client()

    resp = c.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "stream": True,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert resp.status_code == 401
    assert "application/json" in resp.headers["content-type"]
    assert resp.json()["error"]["type"] == "invalid_api_key"
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_openai_stream_mislabel_guard(httpx_mock: Any) -> None:
    """D. Upstream 200 application/json for stream:true must not be labeled SSE."""
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/chat/completions",
        status_code=200,
        json={"choices": [{"message": {"content": "ok"}}]},
        headers={"content-type": "application/json"},
    )
    c = _client()

    resp = c.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "stream": True,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_openai_stream_happy_path(httpx_mock: Any) -> None:
    """C. Multi-event SSE stream passes through incrementally with restoration."""
    placeholder = f"{PH_PREFIX}EMAIL_1{PH_SUFFIX}"
    chunks = [
        {"choices": [{"delta": {"content": f"Reach {placeholder}"}}]},
        {"choices": [{"delta": {"content": " please."}}]},
    ]
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/chat/completions",
        status_code=200,
        headers={"content-type": "text/event-stream"},
        stream=_AsyncStream([_sse_events(*chunks)]),
    )
    c = _client()

    with c.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "stream": True,
            "messages": [{"role": "user", "content": "Reach alice@example.org"}],
        },
    ) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = b"".join(resp.iter_bytes())

    # Restoration should put the original email back into the SSE payload.
    assert b"alice@example.org" in body
    assert placeholder.encode() not in body
    assert b"data: [DONE]\n\n" in body


async def _broken_openai_stream(*_a: Any, **_k: Any) -> StreamResult:
    """Send one complete frame then raise a mid-stream transport error."""

    async def _gen() -> AsyncIterator[bytes]:
        yield b'data: {"choices":[{"delta":{"content":"ok "}}]}\n\n'
        raise httpx.RemoteProtocolError("peer closed")

    return StreamResult(
        status_code=200,
        content_type="text/event-stream",
        headers={},
        iterator=_gen(),
    )


def test_openai_stream_midstream_reset() -> None:
    """B. Mid-stream failure emits exactly one terminal OpenAI error frame."""
    c = _client()
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        new=_broken_openai_stream,
    ):
        with c.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "stream": True,
                "messages": [{"role": "user", "content": "Hello"}],
            },
        ) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            body = b"".join(resp.iter_bytes())

    # At least one complete upstream frame plus a terminal error frame.
    # NB: the OpenAI path re-serializes deltas during placeholder restoration,
    # so assert on content, not byte-exact framing of the relayed event.
    assert b'"content": "ok "' in body
    assert body.rstrip().endswith(_terminal_error_openai().rstrip())
    assert b"data: [DONE]\n\n" in body


async def _empty_broken_openai_stream(*_a: Any, **_k: Any) -> StreamResult:
    """Send one complete frame then raise an empty-message transport error."""

    async def _gen() -> AsyncIterator[bytes]:
        yield b'data: {"choices":[{"delta":{"content":"ok "}}]}\n\n'
        raise httpx.ReadError("")

    return StreamResult(
        status_code=200,
        content_type="text/event-stream",
        headers={},
        iterator=_gen(),
    )


def test_openai_stream_midstream_empty_str_exception_is_typed_in_frame_and_log(
    caplog: Any,
) -> None:
    """Regression: an abrupt upstream close surfaces as httpx.ReadError whose
    str() is EMPTY.  The warning and the terminal frame must still name the
    exception type — a bare empty message made this failure mode invisible.
    """
    c = _client()
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        new=_empty_broken_openai_stream,
    ):
        with caplog.at_level(logging.WARNING, logger="llm_redactor.transport.http_proxy"):
            with c.stream(
                "POST",
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o-mini",
                    "stream": True,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            ) as resp:
                assert resp.status_code == 200
                assert "text/event-stream" in resp.headers["content-type"]
                body = b"".join(resp.iter_bytes())

    assert b'"content": "ok "' in body
    assert b'"message": "ReadError"' in body
    assert any(
        "mid-stream failure" in r.getMessage() and "ReadError" in r.getMessage()
        for r in caplog.records
    )


def test_anthropic_stream_401_propagation(httpx_mock: Any) -> None:
    """A. Anthropic 401 on streaming request returns 401 application/json."""
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/messages",
        status_code=401,
        json={"error": {"type": "invalid_api_key", "message": "bad key"}},
        headers={"content-type": "application/json"},
    )
    c = _client()

    resp = c.post(
        "/v1/messages",
        json={
            "model": "claude-3-5-sonnet",
            "stream": True,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert resp.status_code == 401
    assert "application/json" in resp.headers["content-type"]
    assert resp.json()["error"]["type"] == "invalid_api_key"
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_anthropic_stream_mislabel_guard(httpx_mock: Any) -> None:
    """D. Anthropic upstream 200 application/json for stream:true is not SSE."""
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/messages",
        status_code=200,
        json={"content": [{"type": "text", "text": "ok"}]},
        headers={"content-type": "application/json"},
    )
    c = _client()

    resp = c.post(
        "/v1/messages",
        json={
            "model": "claude-3-5-sonnet",
            "stream": True,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_anthropic_stream_happy_path(httpx_mock: Any) -> None:
    """C. Anthropic SSE events pass through incrementally."""
    events = [
        {"type": "message_start", "message": {"id": "msg_1"}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "ok"}},
        {"type": "message_stop"},
    ]
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/messages",
        status_code=200,
        headers={"content-type": "text/event-stream"},
        stream=_AsyncStream([b"\n".join(f"data: {json.dumps(ev)}\n\n".encode() for ev in events)]),
    )
    c = _client()

    with c.stream(
        "POST",
        "/v1/messages",
        json={
            "model": "claude-3-5-sonnet",
            "stream": True,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    ) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = b"".join(resp.iter_bytes())

    # Events are parsed and re-emitted (default JSON separators), so assert
    # on event content, not byte-exact upstream framing.
    assert b'"type": "message_start"' in body
    assert b'"type": "message_stop"' in body


async def _broken_anthropic_stream(*_a: Any, **_k: Any) -> StreamResult:
    """Send one complete frame then raise a mid-stream transport error."""

    async def _gen() -> AsyncIterator[bytes]:
        yield (
            b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}\n\n'
        )
        raise httpx.RemoteProtocolError("peer closed")

    return StreamResult(
        status_code=200,
        content_type="text/event-stream",
        headers={},
        iterator=_gen(),
    )


def test_anthropic_stream_midstream_reset() -> None:
    """B. Mid-stream failure emits exactly one terminal Anthropic error frame."""
    c = _client()
    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_messages_stream",
        new=_broken_anthropic_stream,
    ):
        with c.stream(
            "POST",
            "/v1/messages",
            json={
                "model": "claude-3-5-sonnet",
                "stream": True,
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "Hello"}],
            },
        ) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            body = b"".join(resp.iter_bytes())

    # At least one complete upstream frame plus a terminal error frame.
    assert b'data: {"type":"content_block_delta"' in body
    assert body.rstrip().endswith(_terminal_error_anthropic().rstrip())
    assert b"event: error\ndata:" in body


async def _empty_broken_anthropic_stream(*_a: Any, **_k: Any) -> StreamResult:
    """Send one complete frame then raise an empty-message transport error."""

    async def _gen() -> AsyncIterator[bytes]:
        yield (
            b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}\n\n'
        )
        raise httpx.ReadError("")

    return StreamResult(
        status_code=200,
        content_type="text/event-stream",
        headers={},
        iterator=_gen(),
    )


def test_anthropic_stream_midstream_empty_str_exception_is_typed_in_frame_and_log(
    caplog: Any,
) -> None:
    """Regression: an abrupt upstream close surfaces as httpx.ReadError whose
    str() is EMPTY.  The warning and the terminal frame must still name the
    exception type — a bare empty message made this failure mode invisible.
    """
    c = _client()
    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_messages_stream",
        new=_empty_broken_anthropic_stream,
    ):
        with caplog.at_level(logging.WARNING, logger="llm_redactor.transport.http_proxy"):
            with c.stream(
                "POST",
                "/v1/messages",
                json={
                    "model": "claude-3-5-sonnet",
                    "stream": True,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            ) as resp:
                assert resp.status_code == 200
                assert "text/event-stream" in resp.headers["content-type"]
                body = b"".join(resp.iter_bytes())

    assert b'data: {"type":"content_block_delta"' in body
    assert b'"message": "ReadError"' in body
    assert any(
        "mid-stream failure" in r.getMessage() and "ReadError" in r.getMessage()
        for r in caplog.records
    )


def test_accept_encoding_clamped_to_local_capability(httpx_mock: Any) -> None:
    """Regression: the proxy consumes upstream bytes before re-serving them,
    so a client's accept-encoding must not be forwarded verbatim — a `br` the
    local httpx cannot decode makes the upstream send undecodable bytes."""
    httpx_mock.add_response(
        status_code=200,
        headers={"content-type": "application/json"},
        json={"choices": [{"message": {"content": "ok"}}]},
    )
    client = _client()
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
        headers={"accept-encoding": "gzip, deflate, br, zstd"},
    )
    assert resp.status_code == 200
    sent = httpx_mock.get_request()
    assert sent is not None
    assert "br" not in sent.headers.get("accept-encoding", "")
    assert "zstd" not in sent.headers.get("accept-encoding", "")
