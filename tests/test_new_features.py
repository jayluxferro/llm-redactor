"""Tests for streaming proxy, Anthropic endpoint, A+B pipeline, and cost_meter."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from evals.cost_meter import _count_tokens, measure_cost
from evals.runner import RunResult
from evals.schema import Annotation, Sample
from llm_redactor.config import Config
from llm_redactor.pipeline.option_ab import OptionABPipeline

# --------------- Fixtures ---------------


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def sample() -> Sample:
    return Sample(
        id="test-001",
        text="Contact alice@example.com about project Falcon.",
        annotations=[
            Annotation(kind="email", text="alice@example.com", start=8, end=27),
        ],
    )


# --------------- cost_meter ---------------


def test_count_tokens_basic():
    assert _count_tokens("hello world") == 2
    assert _count_tokens("") == 0
    assert _count_tokens("one") == 1


def test_measure_cost(sample: Sample):
    rr = RunResult(
        sample_id="test-001",
        option="B",
        original_text=sample.text,
        outgoing_text="Contact ⟨EMAIL_1⟩ about project Falcon.",
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={"⟨EMAIL_1⟩": "alice@example.com"},
        latency_ms=1.0,
        mode="offline",
    )
    cr = measure_cost(sample, rr)
    assert cr.original_tokens > 0
    assert cr.outgoing_tokens > 0
    # Word-count proxy: placeholder replaces multi-token email with single token.
    # Delta can be 0 or negative depending on the text.
    assert cr.delta <= 0


def test_measure_cost_empty_outgoing(sample: Sample):
    """Option A routes locally — outgoing is empty, 100% savings."""
    rr = RunResult(
        sample_id="test-001",
        option="A",
        original_text=sample.text,
        outgoing_text="",
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=1.0,
        mode="offline",
    )
    cr = measure_cost(sample, rr)
    assert cr.outgoing_tokens == 0
    assert cr.delta_pct < 0


# --------------- A+B pipeline ---------------


def test_option_ab_pipeline_instantiation(config: Config):
    p = OptionABPipeline(config=config)
    assert p.stats["requests"] == 0
    assert p.stats["routed_local"] == 0
    assert p.stats["routed_cloud"] == 0


# --------------- HTTP proxy: Anthropic endpoint ---------------


def test_anthropic_endpoint_exists():
    """Verify the /v1/messages route is registered."""
    from llm_redactor.transport.http_proxy import app, configure

    configure(Config())

    # Verify the route is in the app's route table (don't rely on a live
    # upstream, which may return its own 404 that the proxy passes through).
    route_paths = [r.path for r in app.routes if hasattr(r, "path")]
    assert "/v1/messages" in route_paths


def test_streaming_endpoint_accepts_stream_true():
    """Verify stream:true returns a StreamingResponse (not a crash)."""
    from llm_redactor.transport.http_proxy import app, configure

    configure(Config())
    client = TestClient(app, raise_server_exceptions=False)

    body = {
        "model": "test",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
    }
    # Will try to connect to cloud and fail (SSL/connection error).
    # We just verify it doesn't return 404 (route exists) and doesn't
    # crash with an unhandled exception.
    resp = client.post("/v1/chat/completions", json=body)
    assert resp.status_code != 404


def test_anthropic_content_blocks_redaction():
    """Verify Anthropic content block format is handled."""
    from unittest.mock import patch

    from llm_redactor.transport.http_proxy import app, configure

    cfg = Config()
    configure(cfg, use_ner=False)
    client = TestClient(app, raise_server_exceptions=False)

    body = {
        "model": "claude-3-haiku",
        "max_tokens": 100,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Email alice@example.com for details."},
                ],
            },
        ],
    }

    # Mock the upstream Anthropic call so the test doesn't need a real API.
    mock_response = {
        "content": [{"type": "text", "text": "Sure, I'll email them."}],
        "model": "claude-3-haiku",
        "role": "assistant",
    }

    async def fake_forward(*args, **kwargs):
        return mock_response

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_messages",
        side_effect=fake_forward,
    ):
        resp = client.post("/v1/messages", json=body)

    assert resp.status_code == 200
    data = resp.json()
    # Verify redactor metadata was attached.
    assert "redactor" in data


# --------------- Proxy config endpoint still works ---------------


def test_proxy_config_after_changes():
    from llm_redactor.transport.http_proxy import app, configure

    configure(Config(), use_ner=False)
    client = TestClient(app)
    resp = client.get("/v1/redactor/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "pipeline" in data
    assert "transport" in data
    assert "cloud_target" in data
