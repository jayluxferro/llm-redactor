"""Tests for byte-preserving surgical redaction of signed Anthropic bodies."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.detect.types import Span
from llm_redactor.pipeline.option_b import OptionBPipeline
from llm_redactor.redact.placeholder import PREFIX, SUFFIX, PlaceholderGenerator
from llm_redactor.redact.raw_surgery import (
    SSETextRestorer,
    SurgeryError,
    index_string_tokens,
    redact_signed_request,
    restore_response_bytes,
)
from llm_redactor.transport.http_proxy import _get_pipeline, app, configure


def _signed_body(user_text: str, thinking: str = "private reasoning") -> bytes:
    """A minimal /v1/messages body carrying a signed thinking block."""
    return json.dumps(
        {
            "model": "claude-test",
            "max_tokens": 64,
            "stream": False,
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "thinking",
                            "thinking": thinking,
                            "signature": "sig-abc123",
                        },
                        {"type": "text", "text": "prior answer"},
                    ],
                },
                {"role": "user", "content": user_text},
            ],
        }
    ).encode("utf-8")


def _thinking_slice(raw: bytes) -> bytes:
    """Extract the raw bytes of the thinking content string for comparison."""
    doc = json.loads(raw)
    needle = doc["messages"][0]["content"][0]["thinking"]
    idx = raw.find(needle.encode("utf-8"))
    assert idx != -1
    return raw[idx : idx + len(needle.encode("utf-8"))]


def _fake_detect(spans: list[Span]):
    async def detect(text: str) -> list[Span]:
        # Only report spans that actually lie inside the inspected text.
        return [s for s in spans if 0 <= s.start < s.end <= len(text)]

    return detect


def _span_in(text: str, needle: str, kind: str = "email") -> Span:
    start = text.index(needle)
    return Span(
        start=start,
        end=start + len(needle),
        kind=kind,
        confidence=0.99,
        text=needle,
        source="regex",
    )


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


def test_index_tokens_marks_signed_regions_protected() -> None:
    raw = _signed_body("hello john@example.com")
    tokens = index_string_tokens(raw)

    by_tail = {tok.path[-1]: tok for tok in tokens}
    assert by_tail["signature"].protected
    assert by_tail["thinking"].protected
    # The user string content and text blocks stay eligible.
    user_content = [
        tok
        for tok in tokens
        if tok.path[:1] == ("messages",) and tok.path[-1] == "content" and not tok.protected
    ]
    assert any("john@example.com" in tok.value for tok in user_content)
    text_blocks = [tok for tok in tokens if tok.path[-1] == "text" and tok.block_type == "text"]
    assert any(tok.value == "prior answer" for tok in text_blocks)
    thinking_block_texts = [tok for tok in tokens if tok.block_type == "thinking"]
    assert all(tok.protected for tok in thinking_block_texts)


def test_index_tokens_rejects_malformed_json() -> None:
    with pytest.raises(SurgeryError):
        index_string_tokens(b'{"a": "unterminated')


# --------------------------------------------------------------------------- #
# Request-side surgery
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_surgical_redaction_preserves_signed_bytes() -> None:
    user_text = "contact john@example.com please"
    raw = _signed_body(user_text)
    spans = [_span_in(user_text, "john@example.com")]
    original_thinking = _thinking_slice(raw)

    gen = PlaceholderGenerator()
    result = await redact_signed_request(raw, _fake_detect(spans), gen)

    assert result.detections, "detection should be recorded"
    assert result.whole_token_fallbacks == 0
    # Signed region is byte-identical.
    assert _thinking_slice(result.new_raw) == original_thinking
    # Body stays valid JSON with the placeholder in the user text.
    doc = json.loads(result.new_raw)
    user_text = doc["messages"][1]["content"]
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    assert ph in user_text
    assert "john@example.com" not in user_text
    assert result.reverse_map[ph] == "john@example.com"
    # Everything else survives.
    assert doc["messages"][0]["content"][1]["text"] == "prior answer"
    assert doc["messages"][0]["content"][0]["signature"] == "sig-abc123"


@pytest.mark.asyncio
async def test_surgical_redaction_handles_multibyte_prefix() -> None:
    text = "café owner john@example.com wrote"
    raw = _signed_body(text)
    spans = [_span_in(text, "john@example.com")]
    result = await redact_signed_request(raw, _fake_detect(spans), PlaceholderGenerator())
    doc = json.loads(result.new_raw)
    assert "john@example.com" not in doc["messages"][1]["content"]
    assert "café owner" in doc["messages"][1]["content"]
    assert result.whole_token_fallbacks == 0


@pytest.mark.asyncio
async def test_surgical_redaction_maps_simple_escapes_precisely() -> None:
    # Standard escape sequences (\n, \", \\) map precisely — no fallback needed.
    text = 'line1\n"quoted" john@example.com \\ done'
    raw = _signed_body(text)
    spans = [_span_in(text, "john@example.com")]
    result = await redact_signed_request(raw, _fake_detect(spans), PlaceholderGenerator())
    assert result.whole_token_fallbacks == 0
    doc = json.loads(result.new_raw)
    new_text = doc["messages"][1]["content"]
    assert "john@example.com" not in new_text
    assert "line1\n" in new_text and '"quoted"' in new_text
    assert f"{PREFIX}EMAIL_1{SUFFIX}" in new_text


@pytest.mark.asyncio
async def test_surgical_redaction_whole_token_fallback_on_unmappable() -> None:
    # If precise offset mapping is impossible, the entire string value is
    # replaced rather than corrupting the body.
    text = "anything john@example.com here"
    raw = _signed_body(text)
    spans = [_span_in(text, "john@example.com")]

    def broken_map(interior: bytes, decoded_len: int) -> list[int]:
        raise SurgeryError("forced")

    gen = PlaceholderGenerator()
    with patch(
        "llm_redactor.redact.raw_surgery._build_offset_map", new=broken_map
    ):
        result = await redact_signed_request(raw, _fake_detect(spans), gen)
    assert result.whole_token_fallbacks == 1
    doc = json.loads(result.new_raw)
    assert "john@example.com" not in json.dumps(doc)
    assert list(result.reverse_map.values()) == [text]


@pytest.mark.asyncio
async def test_surgical_redaction_skips_signed_content() -> None:
    secret = "sk-supersecret-value"
    raw = _signed_body(f"ignore this", thinking=f"the key is {secret}")
    # Detector claims the secret is present in *any* text it sees; the signed
    # thinking content must still never be modified.
    spans = [
        Span(
            start=0,
            end=len(secret),
            kind="api_key",
            confidence=0.99,
            text=secret,
            source="regex",
        )
    ]
    result = await redact_signed_request(raw, _fake_detect(spans), PlaceholderGenerator())
    assert secret.encode("utf-8") in result.new_raw  # untouched inside thinking
    doc = json.loads(result.new_raw)
    assert doc["messages"][0]["content"][0]["thinking"] == f"the key is {secret}"


# --------------------------------------------------------------------------- #
# Response-side restoration
# --------------------------------------------------------------------------- #


def test_restore_response_preserves_signed_content() -> None:
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    response = json.dumps(
        {
            "content": [
                {
                    "type": "thinking",
                    "thinking": f"the user said {ph}",
                    "signature": "sig-def456",
                },
                {"type": "text", "text": f"I will email {ph} now"},
            ]
        }
    ).encode("utf-8")
    restored = restore_response_bytes(response, {ph: "john@example.com"})
    doc = json.loads(restored)
    # Text block restored...
    assert doc["content"][1]["text"] == "I will email john@example.com now"
    # ...signed thinking untouched (mutating it would break the next turn).
    assert doc["content"][0]["thinking"] == f"the user said {ph}"
    assert doc["content"][0]["signature"] == "sig-def456"


def test_restore_response_handles_escapes_in_replacement() -> None:
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    original = 'weird "quoted" \\ value\nwith newline'
    response = json.dumps({"content": [{"type": "text", "text": f"got {ph}?"}]}).encode("utf-8")
    restored = restore_response_bytes(response, {ph: original})
    doc = json.loads(restored)
    assert doc["content"][0]["text"] == f"got {original}?"


def test_restore_response_noop_without_map() -> None:
    response = b'{"content": []}'
    assert restore_response_bytes(response, {}) == response


# --------------------------------------------------------------------------- #
# Streaming restoration
# --------------------------------------------------------------------------- #


def _delta_event(text: str) -> bytes:
    payload = json.dumps(
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text}},
        separators=(",", ":"),
    )
    return b"data: " + payload.encode("utf-8") + b"\n\n"


def test_sse_restorer_handles_split_placeholders() -> None:
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    restorer = SSETextRestorer({ph: "john@example.com"})
    out = restorer.feed_chunk(_delta_event("mail ") + _delta_event(ph[:5]))
    # Placeholder opening arrived incomplete — hold back.
    assert ph[:5] not in out.decode("utf-8")
    out += restorer.feed_chunk(_delta_event(ph[5:] + " today"))
    text = out.decode("utf-8")
    assert "john@example.com today" in text
    assert ph not in text


def test_sse_restorer_passes_unrelated_brackets_and_signed_events() -> None:
    ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    restorer = SSETextRestorer({ph: "john@example.com"})
    signed_line = (
        b'data: {"type":"thinking_delta","delta":{"type":"text_delta","text":"looks like '
        + ph.encode("utf-8")
        + b'"}}\n\n'
    )
    out = restorer.feed_chunk(_delta_event("math: 3 < 4 and ") + signed_line)
    text = out.decode("utf-8")
    assert "3 < 4 and" in text
    # Signed event passes through byte-identical, placeholder included.
    assert signed_line in out


def test_sse_restorer_flushes_unterminated_hold() -> None:
    restorer = SSETextRestorer({f"{PREFIX}EMAIL_1{SUFFIX}": "john@example.com"})
    emitted = restorer.feed_chunk(_delta_event("dangling " + PREFIX)).decode("utf-8")
    assert "dangling" in emitted
    tail = restorer.flush().decode("utf-8")
    assert PREFIX in tail  # the held bracket is emitted, never dropped


# --------------------------------------------------------------------------- #
# Handler integration (stats + end-to-end signed requests)
# --------------------------------------------------------------------------- #


@pytest.fixture
def client() -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    configure(cfg, use_ner=False)
    return TestClient(app)


def _stats(pipeline: OptionBPipeline) -> dict[str, int]:
    return pipeline.stats


def test_signed_request_with_pii_is_surgically_redacted(client: TestClient) -> None:
    raw = _signed_body("reach me at jane.doe@example.com ok")
    sent: dict[str, bytes] = {}

    async def mock_forward(body_bytes: bytes, config: Any, **kwargs: Any):
        sent["body"] = body_bytes
        return (
            json.dumps(
                {
                    "content": [
                        {"type": "text", "text": f"noted {PREFIX}EMAIL_1{SUFFIX} thanks"}
                    ]
                }
            ).encode("utf-8"),
            200,
            {"content-type": "application/json"},
        )

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_raw",
        new=mock_forward,
    ):
        resp = client.post(
            "/v1/messages",
            content=raw,
            headers={"content-type": "application/json", "x-api-key": "test"},
        )

    assert resp.status_code == 200
    assert resp.headers["x-llm-redactor-mode"] == "signed-surgical"
    # Upstream saw the placeholder, not the address; thinking stayed intact.
    upstream = json.loads(sent["body"])
    assert "jane.doe@example.com" not in json.dumps(upstream)
    assert upstream["messages"][0]["content"][0]["signature"] == "sig-abc123"
    assert upstream["messages"][0]["content"][0]["thinking"] == "private reasoning"
    # Client got the placeholder restored in the response text.
    assert "jane.doe@example.com" in resp.text
    pipeline = _get_pipeline()
    stats = _stats(pipeline)
    assert stats["requests"] == 1
    assert stats["signed_surgical"] == 1
    assert stats["detections"] >= 1
    assert stats["signed_passthrough"] == 0


def test_signed_request_without_detections_passes_through(client: TestClient) -> None:
    raw = _signed_body("nothing sensitive here")

    async def mock_forward(body_bytes: bytes, config: Any, **kwargs: Any):
        assert body_bytes == raw, "clean signed body must be forwarded untouched"
        return b'{"content": []}', 200, {"content-type": "application/json"}

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_raw",
        new=mock_forward,
    ):
        resp = client.post(
            "/v1/messages",
            content=raw,
            headers={"content-type": "application/json", "x-api-key": "test"},
        )

    assert resp.status_code == 200
    assert resp.headers["x-llm-redactor-mode"] == "signed-passthrough"
    stats = _get_pipeline().stats
    assert stats["signed_passthrough"] == 1


def test_unsigned_request_counts_requests_and_detections(client: TestClient) -> None:
    body = {"model": "claude-test", "max_tokens": 8, "messages": [
        {"role": "user", "content": "ping bob@example.com"}
    ]}

    async def mock_forward(outgoing: dict, config: Any, **kwargs: Any):
        return {"content": [{"type": "text", "text": "pong"}]}

    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_messages",
        new=mock_forward,
    ):
        resp = client.post("/v1/messages", json=body, headers={"x-api-key": "test"})

    assert resp.status_code == 200
    stats = _get_pipeline().stats
    assert stats["requests"] >= 1
    assert stats["detections"] >= 1
