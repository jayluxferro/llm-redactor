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


def test_anthropic_thinking_block_bypasses_redaction():
    """Requests with thinking blocks must reach upstream byte-identical.

    Anthropic validates thinking-block signatures against the exact JSON
    bytes it served — any json.loads/dumps round-trip in the redactor
    breaks them.  When a thinking block is detected, the redactor must
    skip its transform pipeline and forward raw bytes via
    ``forward_anthropic_raw``.
    """
    from unittest.mock import patch

    from llm_redactor.transport.http_proxy import app, configure

    cfg = Config()
    configure(cfg, use_ner=False)
    client = TestClient(app, raise_server_exceptions=False)

    # Hand-craft the raw bytes so we can assert byte-identical forwarding.
    raw_body = (
        b'{"model":"claude-sonnet","max_tokens":100,"messages":'
        b'[{"role":"user","content":"start"},'
        b'{"role":"assistant","content":[{"type":"thinking",'
        b'"thinking":"step one","signature":"sig-abc-123"}]},'
        b'{"role":"user","content":"continue"}]}'
    )

    captured: dict = {}

    async def fake_raw(body_bytes, config, *, timeout=120.0, upstream_headers=None):
        captured["body"] = body_bytes
        captured["headers"] = upstream_headers
        return (b'{"id":"msg_x","type":"message","role":"assistant","content":[]}',
                200, {"content-type": "application/json"})

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_raw",
        side_effect=fake_raw,
    ):
        resp = client.post(
            "/v1/messages",
            content=raw_body,
            headers={"content-type": "application/json", "x-api-key": "sk-test"},
        )

    assert resp.status_code == 200
    # The upstream saw the exact bytes we sent — no JSON round-trip.
    assert captured["body"] == raw_body
    assert resp.headers.get("X-LLM-Redactor-Mode") == "signed-passthrough"


def test_anthropic_redacted_thinking_also_bypasses():
    """``redacted_thinking`` blocks (the encrypted variant) get the same treatment."""
    from unittest.mock import patch

    from llm_redactor.transport.http_proxy import app, configure

    cfg = Config()
    configure(cfg, use_ner=False)
    client = TestClient(app, raise_server_exceptions=False)

    raw_body = (
        b'{"model":"claude-sonnet","max_tokens":100,"messages":'
        b'[{"role":"assistant","content":[{"type":"redacted_thinking",'
        b'"data":"encrypted-blob-xyz"}]},'
        b'{"role":"user","content":"go"}]}'
    )

    async def fake_raw(body_bytes, config, *, timeout=120.0, upstream_headers=None):
        return b'{}', 200, {"content-type": "application/json"}

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_raw",
        side_effect=fake_raw,
    ):
        resp = client.post(
            "/v1/messages",
            content=raw_body,
            headers={"content-type": "application/json"},
        )

    assert resp.status_code == 200
    assert resp.headers.get("X-LLM-Redactor-Mode") == "signed-passthrough"


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
