"""Retry contract tests (PIPELINE-RETRY-SPEC.md) for llm-redactor.

Covers the three spec cases:

(a) a ``ReadError`` before the first byte is retried and the request
    eventually succeeds — and the retry re-sends the *same already-redacted*
    body, so nothing is double-redacted and no content is logged;
(b) a non-retryable failure is NOT retried and keeps today's 502 body;
(c) a mid-stream failure yields exactly ONE terminal frame and is never
    retried.

Everything is mocked; no network traffic leaves the test process.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import patch

import anyio
import httpx
import pytest
from fastapi.testclient import TestClient

from llm_redactor import retry
from llm_redactor.config import Config
from llm_redactor.redact.placeholder import PREFIX as PH_PREFIX
from llm_redactor.retry import (
    backoff_seconds,
    is_retryable,
    iter_upstream,
    retry_budget,
    retry_upstream,
)
from llm_redactor.transport.cloud import StreamResult
from llm_redactor.transport.http_proxy import app, configure

EMAIL = "bob@example.com"


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(retry, "_sleep", fake_sleep)
    monkeypatch.delenv("LLM_REDACTOR_UPSTREAM_RETRIES", raising=False)
    return delays


def _client(endpoint: str = "http://test-cloud.invalid/v1") -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    cfg.cloud_target.endpoint = endpoint
    configure(cfg, use_ner=False)
    return TestClient(app)


# ---------------------------------------------------------------------------
# The predicate is type-based, never string-based
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError(""),
        httpx.ConnectTimeout(""),
        httpx.ReadError(""),
        httpx.ReadTimeout(""),
        httpx.WriteError(""),
        httpx.WriteTimeout(""),
        httpx.PoolTimeout(""),
        httpx.RemoteProtocolError(""),
        httpx.CloseError(""),
    ],
)
def test_retryable_transport_errors_match_by_type_even_with_empty_str(exc: Exception) -> None:
    assert is_retryable(exc) is True


def test_non_retryable_errors_are_not_retried_by_type() -> None:
    request = httpx.Request("POST", "http://upstream.invalid/v1/messages")
    response = httpx.Response(429, request=request)
    assert (
        is_retryable(httpx.HTTPStatusError("rate limited", request=request, response=response))
        is False
    )
    assert is_retryable(httpx.TimeoutException("")) is False
    assert is_retryable(ValueError("nope")) is False


def test_end_of_stream_is_retryable() -> None:
    assert is_retryable(anyio.EndOfStream()) is True


# ---------------------------------------------------------------------------
# Budget + backoff
# ---------------------------------------------------------------------------


def test_retry_budget_defaults_to_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_REDACTOR_UPSTREAM_RETRIES", raising=False)
    assert retry_budget() == 2


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("0", 0), ("5", 5), (" 3 ", 3), ("nonsense", 2), ("-4", 0)],
)
def test_retry_budget_env_override(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: int
) -> None:
    monkeypatch.setenv("LLM_REDACTOR_UPSTREAM_RETRIES", raw)
    assert retry_budget() == expected


def test_backoff_is_exponential_jittered_and_never_below_200ms() -> None:
    first = [backoff_seconds(1) for _ in range(200)]
    second = [backoff_seconds(2) for _ in range(200)]
    assert all(0.19 <= d <= 0.31 for d in first)
    assert all(0.39 <= d <= 0.61 for d in second)
    assert all(d >= 0.2 for d in first + second)
    assert backoff_seconds(10) <= 2.0


# ---------------------------------------------------------------------------
# Helper behaviour
# ---------------------------------------------------------------------------


async def test_retry_upstream_retries_read_error_then_succeeds(
    _no_real_sleep: list[float],
) -> None:
    calls: list[int] = []

    async def call() -> str:
        calls.append(1)
        if len(calls) < 3:
            raise httpx.ReadError("")  # str() is EMPTY
        return "ok"

    assert await retry_upstream(call, operation="test") == "ok"
    assert len(calls) == 3
    assert len(_no_real_sleep) == 2


async def test_retry_upstream_is_bounded_and_reraises_the_last_error() -> None:
    calls: list[int] = []

    async def call() -> None:
        calls.append(1)
        raise httpx.ReadError("")

    with pytest.raises(httpx.ReadError):
        await retry_upstream(call, operation="test")
    assert len(calls) == 3


async def test_retry_upstream_passes_non_retryable_errors_straight_through() -> None:
    calls: list[int] = []

    async def call() -> None:
        calls.append(1)
        raise httpx.HTTPStatusError(
            "bad gateway",
            request=httpx.Request("POST", "http://upstream.invalid"),
            response=httpx.Response(502),
        )

    with pytest.raises(httpx.HTTPStatusError):
        await retry_upstream(call, operation="test")
    assert len(calls) == 1


async def test_iter_upstream_does_not_retry_after_first_item(
    _no_real_sleep: list[float],
) -> None:
    attempts: list[int] = []

    async def stream_factory() -> AsyncIterator[int]:
        attempts.append(1)
        yield 1
        raise httpx.ReadError("")

    received: list[int] = []
    with pytest.raises(httpx.ReadError):
        async for item in iter_upstream(stream_factory, operation="test"):
            received.append(item)
    assert received == [1]
    assert len(attempts) == 1
    assert _no_real_sleep == []


# ---------------------------------------------------------------------------
# (a) read error before the first byte → retried, same redacted body re-sent
# ---------------------------------------------------------------------------

_CHAT_BODY: dict[str, Any] = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": f"please email {EMAIL}"}],
    "stream": False,
}


def test_chat_completion_retries_read_error_without_double_redaction(
    httpx_mock: Any, caplog: Any
) -> None:
    httpx_mock.add_exception(httpx.ReadError(""))  # str() is EMPTY
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/chat/completions",
        status_code=200,
        json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        headers={"content-type": "application/json"},
    )
    client = _client()

    with caplog.at_level("WARNING"):
        resp = client.post("/v1/chat/completions", json=_CHAT_BODY)

    assert resp.status_code == 200
    sent = httpx_mock.get_requests()
    assert len(sent) == 2  # one retry, same upstream call
    # PII: the retry re-sent the identical, already-redacted body — redaction
    # never ran twice, so there is exactly one placeholder and no raw email.
    assert sent[0].content == sent[1].content
    assert EMAIL.encode() not in sent[0].content
    assert sent[0].content.count(PH_PREFIX.encode()) == 1
    # PII: retry logging names the exception type and nothing else.
    retry_lines = [r.getMessage() for r in caplog.records if "retrying upstream" in r.getMessage()]
    assert retry_lines and "ReadError" in retry_lines[0]
    assert all(EMAIL not in line for line in caplog.text.splitlines())
    assert all(PH_PREFIX not in line for line in retry_lines)


def test_chat_completion_retries_are_bounded(httpx_mock: Any) -> None:
    for _ in range(3):
        httpx_mock.add_exception(httpx.ReadError(""))
    hx = _client()

    # Bounded: exactly 1 attempt + 2 retries, then the error propagates
    # unchanged (the non-streaming pipeline path does not translate transport
    # errors today — this change deliberately does not alter that outcome).
    with pytest.raises(httpx.ReadError):
        hx.post("/v1/chat/completions", json=_CHAT_BODY)

    assert len(httpx_mock.get_requests()) == 3


# ---------------------------------------------------------------------------
# (b) non-retryable → not retried, today's 502 body preserved
# ---------------------------------------------------------------------------


def test_raw_passthrough_non_retryable_error_is_sent_once(httpx_mock: Any) -> None:
    httpx_mock.add_exception(httpx.DecodingError("bad bytes"))
    client = _client()

    resp = client.post(
        "/v1/messages/count_tokens",
        content=b'{"model":"claude-3-5-sonnet","messages":[]}',
        headers={"content-type": "application/json", "x-api-key": "sk-test"},
    )

    assert len(httpx_mock.get_requests()) == 1  # no retry
    assert resp.status_code == 502
    assert resp.json() == {
        "error": {"type": "upstream_error", "message": "DecodingError: bad bytes"}
    }


def test_upstream_4xx_is_passed_through_not_retried(httpx_mock: Any) -> None:
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/messages/count_tokens",
        status_code=429,
        json={"error": {"type": "rate_limit_error"}},
        headers={"content-type": "application/json", "retry-after": "7"},
    )
    client = _client()

    resp = client.post(
        "/v1/messages/count_tokens",
        content=b'{"model":"claude-3-5-sonnet","messages":[]}',
        headers={"content-type": "application/json", "x-api-key": "sk-test"},
    )

    assert len(httpx_mock.get_requests()) == 1
    assert resp.status_code == 429
    assert resp.headers.get("retry-after") == "7"


# ---------------------------------------------------------------------------
# (c) mid-stream failure → one terminal frame, never a retry
# ---------------------------------------------------------------------------


async def _broken_openai_stream(*_a: Any, **_k: Any) -> StreamResult:
    _broken_openai_stream.calls += 1  # type: ignore[attr-defined]

    async def _gen() -> AsyncIterator[bytes]:
        yield b'data: {"choices":[{"delta":{"content":"ok "}}]}\n\n'
        raise httpx.ReadError("")

    return StreamResult(
        status_code=200,
        content_type="text/event-stream",
        headers={},
        iterator=_gen(),
    )


_broken_openai_stream.calls = 0  # type: ignore[attr-defined]


def test_midstream_failure_emits_one_terminal_frame_and_never_retries(
    _no_real_sleep: list[float],
) -> None:
    _broken_openai_stream.calls = 0
    client = _client()
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        new=_broken_openai_stream,
    ):
        with client.stream(
            "POST",
            "/v1/chat/completions",
            json={**_CHAT_BODY, "stream": True},
        ) as resp:
            assert resp.status_code == 200
            body = b"".join(resp.iter_bytes())

    # One upstream stream opened, no second attempt after commit.
    assert _broken_openai_stream.calls == 1
    assert _no_real_sleep == []
    # Exactly one terminal error frame, and it is the last thing before [DONE].
    assert body.count(b'"error"') == 1
    assert b"ReadError" in body
    frames = [f for f in body.split(b"\n\n") if f.strip()]
    assert b'"message": "ReadError"' in frames[-2]
    assert frames[-1] == b"data: [DONE]"


def test_anthropic_midstream_failure_emits_one_terminal_frame() -> None:
    calls: list[int] = []

    async def broken(*_a: Any, **_k: Any) -> StreamResult:
        calls.append(1)

        async def _gen() -> AsyncIterator[bytes]:
            yield (
                b'data: {"type":"content_block_delta",'
                b'"delta":{"type":"text_delta","text":"ok"}}\n\n'
            )
            raise httpx.ReadError("")

        return StreamResult(
            status_code=200,
            content_type="text/event-stream",
            headers={},
            iterator=_gen(),
        )

    client = _client()
    with patch("llm_redactor.transport.http_proxy.forward_anthropic_messages_stream", new=broken):
        with client.stream(
            "POST",
            "/v1/messages",
            json={
                "model": "claude-3-5-sonnet",
                "stream": True,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": f"email {EMAIL}"}],
            },
        ) as resp:
            assert resp.status_code == 200
            body = b"".join(resp.iter_bytes())

    assert len(calls) == 1  # committed stream: no retry
    assert body.count(b"event: error") == 1
    assert b'"message": "ReadError"' in body


# ---------------------------------------------------------------------------
# Cloud layer: retry happens at the send, before Gate 1 commits to SSE
# ---------------------------------------------------------------------------


async def test_forward_chat_completion_stream_retries_before_commit(
    httpx_mock: Any, _no_real_sleep: list[float]
) -> None:
    from llm_redactor.transport.cloud import forward_chat_completion_stream

    httpx_mock.add_exception(httpx.ReadError(""))
    httpx_mock.add_response(
        url="http://test-cloud.invalid/v1/chat/completions",
        status_code=200,
        headers={"content-type": "text/event-stream"},
        content=b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n',
    )
    cfg = Config()
    cfg.cloud_target.endpoint = "http://test-cloud.invalid/v1"

    result = await forward_chat_completion_stream(
        {"model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": True},
        cfg.cloud_target,
    )

    assert result.status_code == 200
    assert result.iterator is not None
    chunks = [c async for c in result.iterator]
    assert b"".join(chunks)
    assert len(httpx_mock.get_requests()) == 2
    assert len(_no_real_sleep) == 1
