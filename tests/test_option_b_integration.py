"""Integration tests for Option B end-to-end pipeline.

Tests the full flow: POST with sensitive content → redacted outgoing → restored response.
Uses a mock cloud server (httpx mock) to capture what was actually sent.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

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
                    "Email bob@corp.com about the meeting. "
                    "CC bob@corp.com on the follow-up."
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
                    "Contact alice@example.org or call 555-123-4567. "
                    "Key: AKIAIOSFODNN7EXAMPLE"
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
        start=8, end=25, kind="email", confidence=0.3,
        text="alice@example.org", source="test",
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
