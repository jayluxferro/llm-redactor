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
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "private_key_pem" in kinds


def test_no_false_positive_on_plain_text():
    spans = detect_regex("This is a normal sentence with no secrets.")
    assert len(spans) == 0


def test_detects_pem_full_block():
    text = (
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n'
        "MIIEpAIBAAKCAQEA0Aq4X9Zdeadbeef==\\n"
        '-----END RSA PRIVATE KEY-----"'
    )
    spans = detect_regex(text)
    pem = next(s for s in spans if s.kind == "private_key_pem")
    assert "MIIEpAIBAAKCAQEA" in pem.text
    assert "-----END RSA PRIVATE KEY-----" in pem.text


def test_detects_password_value_with_spaces():
    spans = detect_regex('PASSWORD="my secret passphrase here"')
    pw = next(s for s in spans if s.kind == "password")
    assert pw.text == "my secret passphrase here"


def test_detects_telegram_bot_token():
    spans = detect_regex("TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ1234567")
    tok = next(s for s in spans if s.kind == "telegram_bot_token")
    assert ":" in tok.text and len(tok.text) == 43


def test_detects_fine_grained_github_pat():
    body22 = "AbCdEfGhIjKlMnOpQrStUv"
    body59 = "a" * 59
    spans = detect_regex(f"GITHUB_TOKEN=github_pat_{body22}_{body59}")
    kinds = {s.kind for s in spans}
    assert "github_token" in kinds


def test_detects_discord_token():
    spans = detect_regex("DISCORD_TOKEN=" + "MTA" + "f" * 50)
    kinds = {s.kind for s in spans}
    assert "discord_token" in kinds
