"""Integration tests for Option B end-to-end pipeline.

Tests the full flow: POST with sensitive content → redacted outgoing → restored response.
Uses a mock cloud server (httpx mock) to capture what was actually sent.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.pipeline.option_b import OptionBPipeline, RefusalError
from llm_redactor.redact.placeholder import PREFIX, SUFFIX
from llm_redactor.transport.http_proxy import app, configure

# --- Pipeline unit tests (no HTTP) ---


@pytest.fixture
def config() -> Config:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False  # don't refuse in tests
    return cfg


@pytest.fixture
def pipeline(config: Config) -> OptionBPipeline:
    return OptionBPipeline(config=config, use_ner=False)


def _mock_cloud_response(content: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


@pytest.mark.asyncio
async def test_pipeline_redacts_email(pipeline: OptionBPipeline):
    """Email in user message should be replaced with placeholder in the outgoing request."""
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Send a message to alice@example.org about the project."},
        ],
    }

    placeholder = f"{PREFIX}EMAIL_1{SUFFIX}"
    cloud_response_content = f"I'll email {placeholder} about the project."

    captured_body: dict[str, Any] = {}

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        captured_body.update(outgoing)
        # Verify the outgoing request has the placeholder, not the real email.
        outgoing_content = outgoing["messages"][0]["content"]
        assert "alice@example.org" not in outgoing_content
        assert placeholder in outgoing_content
        return _mock_cloud_response(cloud_response_content)

    with patch(
        "llm_redactor.pipeline.option_b.forward_chat_completion",
        side_effect=mock_forward,
    ):
        result = await pipeline.run(body)

    # The restored response should contain the real email.
    response_content = result.response["choices"][0]["message"]["content"]
    assert "alice@example.org" in response_content
    assert placeholder not in response_content

    # Leak audit should show zero leakage.
    assert result.leak_audit["sensitive_tokens_sent"] == 0
    assert result.leak_audit["sensitive_tokens_detected"] >= 1


@pytest.mark.asyncio
async def test_pipeline_coreference_stability(pipeline: OptionBPipeline):
    """Two mentions of the same email should get the same placeholder."""
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Email bob@corp.com about the meeting. CC bob@corp.com on the follow-up."
                ),
            },
        ],
    }

    placeholder = f"{PREFIX}EMAIL_1{SUFFIX}"

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        content = outgoing["messages"][0]["content"]
        assert content.count(placeholder) == 2
        return _mock_cloud_response(f"I'll email {placeholder} and CC {placeholder}.")

    with patch(
        "llm_redactor.pipeline.option_b.forward_chat_completion",
        side_effect=mock_forward,
    ):
        result = await pipeline.run(body)

    response_content = result.response["choices"][0]["message"]["content"]
    assert response_content.count("bob@corp.com") == 2


@pytest.mark.asyncio
async def test_pipeline_no_sensitive_content(pipeline: OptionBPipeline):
    """Request with no sensitive content passes through unmodified."""
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"},
        ],
    }

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        assert outgoing["messages"][0]["content"] == "What is the capital of France?"
        return _mock_cloud_response("The capital of France is Paris.")

    with patch(
        "llm_redactor.pipeline.option_b.forward_chat_completion",
        side_effect=mock_forward,
    ):
        result = await pipeline.run(body)

    assert result.leak_audit["sensitive_tokens_detected"] == 0
    assert result.options_applied == ["B"]


@pytest.mark.asyncio
async def test_pipeline_multiple_pii_types(pipeline: OptionBPipeline):
    """Multiple PII types in one message should all be redacted."""
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Contact alice@example.org or call 555-123-4567. Key: AKIAIOSFODNN7EXAMPLE"
                ),
            },
        ],
    }

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        content = outgoing["messages"][0]["content"]
        assert "alice@example.org" not in content
        assert "AKIAIOSFODNN7EXAMPLE" not in content
        return _mock_cloud_response("Got it.")

    with patch(
        "llm_redactor.pipeline.option_b.forward_chat_completion",
        side_effect=mock_forward,
    ):
        result = await pipeline.run(body)

    assert result.leak_audit["sensitive_tokens_detected"] >= 2


@pytest.mark.asyncio
async def test_strict_mode_refuses_low_confidence():
    """Strict mode should raise RefusalError on low-confidence detections."""
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = True
    pipeline = OptionBPipeline(config=cfg)

    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Contact alice@example.org please."},
        ],
    }

    # Patch detect_all to return a low-confidence span.
    from llm_redactor.detect.types import Span

    low_conf_span = Span(
        start=8,
        end=25,
        kind="email",
        confidence=0.3,
        text="alice@example.org",
        source="test",
    )

    with (
        patch(
            "llm_redactor.pipeline.option_b.detect_all",
            return_value=[low_conf_span],
        ),
        pytest.raises(RefusalError) as exc_info,
    ):
        await pipeline.run(body)

    assert exc_info.value.reason == "low_confidence_detection"


# --- HTTP proxy integration tests ---


@pytest.fixture
def client() -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    configure(cfg, use_ner=False)
    return TestClient(app)


def test_http_proxy_redacts_and_restores(client: TestClient):
    """Full HTTP round-trip: POST → redact → cloud → restore → response."""
    placeholder = f"{PREFIX}EMAIL_1{SUFFIX}"

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        content = outgoing["messages"][0]["content"]
        assert "alice@example.org" not in content
        return _mock_cloud_response(f"Done, notified {placeholder}.")

    with patch(
        "llm_redactor.pipeline.option_b.forward_chat_completion",
        side_effect=mock_forward,
    ):
        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "user", "content": "Notify alice@example.org."},
                ],
            },
        )

    assert resp.status_code == 200
    assert resp.headers.get("X-LLM-Redactor-Mode") == "redacted"
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    assert "alice@example.org" in content
    assert data["redactor"]["options_applied"] == ["B"]
    assert data["redactor"]["leak_audit"]["sensitive_tokens_sent"] == 0


def test_http_proxy_stats(client: TestClient):
    """Stats endpoint returns counters."""
    resp = client.get("/v1/redactor/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "requests" in data
    assert "detections" in data


def test_http_proxy_refuses_tools_when_policy_refuse() -> None:
    """tools_policy=refuse returns 422 without contacting upstream."""
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    cfg.transport.tools_policy = "refuse"
    configure(cfg, use_ner=False)
    c = TestClient(app)
    body: dict[str, Any] = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "fn",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        ],
    }
    r = c.post("/v1/chat/completions", json=body)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["reason"] == "tools_or_functions_present"


async def _fake_sse_stream(*_a: Any, **_k: Any):
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    ev: dict[str, Any] = {"choices": [{"delta": {"content": f"notified {ph}"}}]}
    yield f"data: {json.dumps(ev)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def test_openai_stream_restores_placeholders() -> None:
    """Golden SSE path: placeholder in model delta is restored before client sees it."""
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    configure(cfg, use_ner=False)
    c = TestClient(app)
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        new=_fake_sse_stream,
    ):
        with c.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "stream": True,
                "messages": [{"role": "user", "content": "Notify alice@example.org."}],
            },
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers.get("x-llm-redactor-mode") == "redacted"
            raw = b"".join(resp.iter_bytes())

    assert b"alice@example.org" in raw


async def _fake_sse_stream_split_placeholder(*_a: Any, **_k: Any):
    """Upstream sends the redacted placeholder split across two SSE deltas."""
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    mid = max(1, len(ph) // 2)
    ev1 = {"choices": [{"delta": {"content": f"notified {ph[:mid]}"}}]}
    ev2 = {"choices": [{"delta": {"content": f"{ph[mid:]} today."}}]}
    yield f"data: {json.dumps(ev1)}\n\n".encode()
    yield f"data: {json.dumps(ev2)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def test_openai_stream_splits_placeholder_across_chunks() -> None:
    """Restoration must tolerate placeholders split across SSE chunk boundaries."""
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    configure(cfg, use_ner=False)
    c = TestClient(app)
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        new=_fake_sse_stream_split_placeholder,
    ):
        with c.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "stream": True,
                "messages": [{"role": "user", "content": "Notify alice@example.org."}],
            },
        ) as resp:
            assert resp.status_code == 200
            raw = b"".join(resp.iter_bytes())

    assert b"alice@example.org" in raw


def test_http_proxy_tools_bypass_sets_header() -> None:
    """Transparent tool forward includes bypass response headers."""
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    cfg.transport.tools_policy = "bypass"
    configure(cfg, use_ner=False)
    c = TestClient(app)

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any) -> dict:
        return _mock_cloud_response("ok")

    with patch(
        "llm_redactor.transport.cloud.forward_chat_completion",
        side_effect=mock_forward,
    ):
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "x"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "t",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    },
                ],
            },
        )
    assert resp.status_code == 200
    assert resp.headers.get("X-LLM-Redactor-Mode") == "bypass-tools"
    assert resp.headers.get("X-LLM-Redactor-Bypass-Reason") == "tools-or-functions"
