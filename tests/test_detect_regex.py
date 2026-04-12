"""Tests for regex-based detection."""

from __future__ import annotations

from llm_redactor.detect.regex import detect_regex


def test_detects_email():
    spans = detect_regex("Contact alice@example.org for details.")
    assert len(spans) == 1
    assert spans[0].kind == "email"
    assert spans[0].text == "alice@example.org"


def test_detects_aws_access_key():
    text = "key = AKIAIOSFODNN7EXAMPLE"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "aws_access_key" in kinds


def test_detects_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "bearer_token" in kinds


def test_detects_pem_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "pem_private_key" in kinds


def test_no_false_positive_on_plain_text():
    spans = detect_regex("This is a normal sentence with no secrets.")
    assert len(spans) == 0
