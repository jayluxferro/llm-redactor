"""Tests for placeholder redaction and restoration."""

from __future__ import annotations

from llm_redactor.detect.types import Span
from llm_redactor.redact.placeholder import PREFIX, SUFFIX, redact
from llm_redactor.redact.restore import restore


def _span(start: int, end: int, kind: str, text: str) -> Span:
    return Span(start=start, end=end, kind=kind, confidence=1.0, text=text, source="test")


def test_redact_single_email():
    text = "Contact alice@example.org please."
    spans = [_span(8, 25, "email", "alice@example.org")]
    result = redact(text, spans)

    expected_ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    assert expected_ph in result.redacted_text
    assert "alice@example.org" not in result.redacted_text
    assert result.reverse_map[expected_ph] == "alice@example.org"


def test_coreference_stability():
    text = "Email alice@example.org and cc alice@example.org."
    spans = [
        _span(6, 23, "email", "alice@example.org"),
        _span(31, 48, "email", "alice@example.org"),
    ]
    result = redact(text, spans)

    # Both occurrences should map to the same placeholder.
    expected_ph = f"{PREFIX}EMAIL_1{SUFFIX}"
    assert result.redacted_text.count(expected_ph) == 2
    assert len(result.reverse_map) == 1


def test_restore_roundtrip():
    text = "Contact alice@example.org please."
    spans = [_span(8, 25, "email", "alice@example.org")]
    result = redact(text, spans)

    response = f"I will email {PREFIX}EMAIL_1{SUFFIX} right away."
    restored = restore(response, result.reverse_map)
    assert "alice@example.org" in restored
    assert PREFIX not in restored


def test_empty_spans():
    text = "Nothing sensitive here."
    result = redact(text, [])
    assert result.redacted_text == text
    assert result.reverse_map == {}


def test_session_tag_in_placeholder():
    text = "Contact alice@example.org please."
    spans = [_span(8, 25, "email", "alice@example.org")]
    result = redact(text, spans, session_tag="a1b2c3d")

    expected_ph = f"{PREFIX}EMAIL_1\u00b7a1b2c3d{SUFFIX}"
    assert expected_ph in result.redacted_text
    assert result.reverse_map[expected_ph] == "alice@example.org"
    restored = restore(f"Sent to {expected_ph}.", result.reverse_map)
    assert "alice@example.org" in restored
