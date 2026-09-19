"""Deterministic rules backend: per-kind validators, wiring, and fail-open."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from llm_redactor.config import Config, LLMValidationConfig, load_config
from llm_redactor.detect.orchestrator import detect_all_validated
from llm_redactor.detect.rules_validator import RULES, validate_spans_rules
from llm_redactor.detect.types import Span
from llm_redactor.pipeline.option_b import OptionBPipeline
from llm_redactor.transport import mcp_server

# A 12-digit string that passes Luhn (check digit chosen for the prefix) —
# proves the length floor rejects it, not the checksum.
_SHORT_VALID_LUHN = "411111111117"


def _span(kind: str, text: str, source: str = "regex", confidence: float = 1.0) -> Span:
    return Span(start=0, end=len(text), kind=kind, confidence=confidence, text=text, source=source)


def _keep(kind: str, text: str, source: str = "regex") -> None:
    assert RULES[kind](text) is True


def _drop(kind: str, text: str, source: str = "regex") -> None:
    assert RULES[kind](text) is False


# --- reference implementations (independent of the module under test) --------


def _ref_luhn(digits: str) -> bool:
    """Textbook Luhn over an integer sum, no cleverness."""
    total = 0
    for pos, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if pos % 2 else 1)
        total += (d - 9) if d > 9 else d
    return total % 10 == 0


def _ref_iban_mod97(iban: str) -> int:
    """One-big-integer mod-97 (contrast with the module's streaming mod)."""
    s = iban.replace(" ", "").upper()
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)  # letters → 10-35, digits as-is
    return int(num) % 97  # valid IBANs give 1


# --- credit_card -------------------------------------------------------------


def test_credit_card_luhn_valid_kept():
    _keep("credit_card", "4532015112830366")
    _keep("credit_card", "4111 1111 1111 1111")  # separators must be stripped
    _keep("credit_card", "3782-8224-6310-005")  # 15-digit Amex
    assert all(_ref_luhn(d) for d in ("4532015112830366", "4111111111111111", "378282246310005"))


def test_credit_card_luhn_invalid_dropped():
    _drop("credit_card", "4111111111111112")  # single-digit flip breaks the checksum
    _drop("credit_card", "4532-0151-1283-0367")  # separators don't rescue a bad checksum


def test_credit_card_length_bounds():
    assert _ref_luhn(_SHORT_VALID_LUHN) is True
    _drop("credit_card", _SHORT_VALID_LUHN)  # 12 digits: Luhn-valid but too short
    _drop("credit_card", "41111111111111111111")  # 20 digits: too long


# --- iban --------------------------------------------------------------------


def test_iban_valid_kept_and_checksum_verified_independently():
    vectors = ["GB82WEST12345698765432", "DE89370400440532013000", "NL91ABNA0417164300"]
    for iban in vectors:
        # The known-good pair: reference mod-97 says 1, rule agrees.
        assert _ref_iban_mod97(iban) == 1
        _keep("iban", iban, source="ner")
    _keep("iban", "GB82 WEST 1234 5698 7654 32", source="ner")  # spaced form


def test_iban_bad_check_digit_dropped():
    bad = "GB83WEST12345698765432"  # check digits 82 → 83
    assert _ref_iban_mod97(bad) != 1
    _drop("iban", bad, source="ner")


# --- ssn ---------------------------------------------------------------------


def test_ssn_valid_kept():
    _keep("ssn", "123-45-6789", source="ner")
    _keep("ssn", "123456789", source="ner")


def test_ssn_structurally_impossible_dropped():
    _drop("ssn", "000-45-6789", source="ner")  # area 000: never issued
    _drop("ssn", "123-00-6789", source="ner")  # group 00: never issued
    _drop("ssn", "123-45-0000", source="ner")  # serial 0000: never issued


def test_ssn_itin_and_historic_areas_kept():
    """Regression (hostile review): 900-999 areas are ITINs and 666 was
    historically allocated — valid, SENSITIVE taxpayer identifiers.  The
    old rule dropped them in rules mode = leaked them unredacted."""
    _keep("ssn", "900-45-6789", source="ner")  # ITIN
    _keep("ssn", "912-45-6789", source="ner")  # ITIN
    _keep("ssn", "666-45-6789", source="ner")  # historically allocated


def test_key_band_below_old_floor_never_dropped():
    """Regression (hostile review, C1): the old _key_like 20-char floor
    silently unredacted REAL regex-detected credentials in the [15,20)
    band — generic_api_key matches {16,} and slack tokens run 15 chars.
    The rule must never drop something the detector legitimately found."""
    _keep("generic_api_key", "a3f8k2m9x1p4q7z2", source="regex")  # 16 chars
    _keep("slack_token", "xoxb-0123456789-12", source="regex")  # 15+ chars
    _keep("openai_api_key", "sk-proj-short1", source="regex")
    # Whitespace still means prose, not a key.
    _drop("generic_api_key", "not a key at all here", source="regex")


# --- email -------------------------------------------------------------------


def test_email_valid_kept():
    _keep("email", "alice@example.com", source="ner")
    _keep("email", "a.b+tag@sub.example.co.uk", source="ner")


def test_email_malformed_dropped():
    _drop("email", "a..b@example.com", source="ner")  # consecutive dots
    _drop("email", ".alice@example.com", source="ner")  # leading dot
    _drop("email", "alice@example.com.", source="ner")  # trailing dot
    _drop("email", "alice@localhost", source="ner")  # no dot in domain


# --- phones ------------------------------------------------------------------


def test_phone_us_digit_counts():
    _keep("phone_us", "(415) 555-2671")
    _keep("phone_us", "1-415-555-2671")  # 11 digits with leading 1
    _drop("phone_us", "415-555-267")  # 9 digits


def test_phone_intl_requires_prefix_and_8_to_15_digits():
    _keep("phone_intl", "+44 20 7946 0958")
    _keep("phone_intl", "0044 20 7946 0958")
    _drop("phone_intl", "20 7946 0958")  # no +/00 prefix
    _drop("phone_intl", "+44 20 9")  # too few digits


def test_phone_ner_kind_is_digit_count_only():
    # Presidio flags prefix-less US-style numbers too; dropping those would
    # leak them, so the NER ``phone`` kind only gets the digit-count check.
    _keep("phone", "(650) 253-0000", source="ner")
    _keep("phone", "+1 650 253 0000", source="ner")
    _drop("phone", "555", source="ner")


# --- jwt ---------------------------------------------------------------------


def test_jwt_three_segments_kept_two_dropped():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    _keep("jwt", token)
    _drop("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ")


# --- key-shaped kinds --------------------------------------------------------


def test_generic_api_key_shape():
    """Length floors live in the DETECTING REGEXES ({16,} for this kind) —
    a rule floor above them drops real detected secrets (C1).  The rule's
    remaining job: whitespace ⇒ prose, not a key."""
    _keep("generic_api_key", "j9K2mN4pQ7rS1tU3vW5xYz")
    _keep("generic_api_key", "AKIAIOSFODNN7EXAMPLE")  # vendor kinds share the rule
    _keep("generic_api_key", "short123")  # under the REGEX floor this span can't be regex-sourced; keep-safe for NER oddities
    _keep("generic_api_key", "--------------------")
    _drop("generic_api_key", "one two three four five6")  # whitespace ⇒ prose, not a key


def test_vendor_keys_share_the_floor():
    assert RULES["github_token"] is RULES["openai_api_key"] is RULES["generic_api_key"]


# --- passthrough & fail-open --------------------------------------------------


def test_kinds_without_rules_pass_through_unchanged():
    spans = [
        _span("person", "Maria Garcia-Lopez", source="ner", confidence=0.9),
        _span("location", "Kumasi", source="ner", confidence=0.8),
        _span("nationality", "Ghanaian", source="ner", confidence=0.7),
        _span("date_time", "next Tuesday", source="ner", confidence=0.6),
        _span("url", "https://example.com/x", source="regex"),
        _span("ip_v4", "192.168.1.1", source="regex"),
    ]
    assert validate_spans_rules(spans) == spans


def test_raising_rule_keeps_span():
    def boom(_text: str) -> bool:
        raise RuntimeError("buggy rule")

    spans = [_span("email", "alice@example.com", source="ner")]
    with patch.dict(RULES, {"email": boom}):
        assert validate_spans_rules(spans) == spans


def test_regex_source_bad_luhn_credit_card_is_dropped():
    """The upgrade: regex spans are no longer auto-kept by the rules backend."""
    spans = [_span("credit_card", "4111111111111112", source="regex")]
    assert validate_spans_rules(spans) == []


# --- backend wiring -----------------------------------------------------------


def _rules_config() -> Config:
    cfg = Config()
    cfg.pipeline.llm_validation.enabled = True
    cfg.pipeline.llm_validation.backend = "rules"
    return cfg


async def _assert_no_ollama(*_args: object, **_kwargs: object) -> list[Span]:
    raise AssertionError("rules backend must not call the Ollama validator")


@pytest.mark.asyncio
async def test_option_b_rules_backend_makes_no_ollama_call():
    # Deterministic bad-Luhn card; the uuid keeps this text out of the
    # process-wide detection cache that other tests may have filled.
    text = f"Invoice {uuid.uuid4().hex[:8]}: charge 4111111111111112 for alice@example.com."
    pipeline = OptionBPipeline(config=_rules_config(), use_ner=False)

    with patch(
        "llm_redactor.detect.llm_validator.validate_spans",
        side_effect=_assert_no_ollama,
    ):
        spans = await pipeline.detect_spans(text)

    by_kind = {s.kind for s in spans}
    assert "credit_card" not in by_kind  # bad Luhn dropped end-to-end
    assert "email" in by_kind  # the valid span beside it survives


@pytest.mark.asyncio
async def test_mcp_rules_backend_makes_no_ollama_call(monkeypatch: pytest.MonkeyPatch):
    text = f"Card on file 4111111111111112, ticket {uuid.uuid4().hex[:8]}."
    monkeypatch.setattr(mcp_server, "_config", _rules_config())
    monkeypatch.setattr("llm_redactor.detect.llm_validator.validate_spans", _assert_no_ollama)

    spans = await mcp_server._detect_text(text, use_ner=False, use_llm_validation=True)

    assert "credit_card" not in [s.kind for s in spans]


@pytest.mark.asyncio
async def test_model_backend_still_routes_to_ollama_validator():
    seen: dict[str, object] = {}

    async def fake_validate(_text: str, spans: list[Span], **kwargs: object) -> list[Span]:
        seen["kwargs"] = kwargs
        return spans

    with (
        patch("llm_redactor.detect.orchestrator.detect_ner", return_value=[]),
        patch("llm_redactor.detect.llm_validator.validate_spans", side_effect=fake_validate),
    ):
        spans = await detect_all_validated("mail alice@example.com", use_ner=True)

    assert [s.kind for s in spans] == ["email"]
    assert seen["kwargs"] == {"endpoint": "http://127.0.0.1:11434", "model": "llama3.2:3b"}


@pytest.mark.asyncio
async def test_unknown_backend_fails_loudly():
    with pytest.raises(ValueError, match="backend"):
        await detect_all_validated("x", use_ner=False, backend="neural")


def test_config_rejects_unknown_backend():
    with pytest.raises(ValueError, match="backend"):
        LLMValidationConfig(backend="neural")


def test_config_loads_backend_from_yaml(tmp_path: Path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("pipeline:\n  llm_validation:\n    enabled: true\n    backend: rules\n")
    cfg = load_config(cfg_file)
    assert cfg.pipeline.llm_validation.backend == "rules"


def test_api_key_env_field_rejects_pasted_secrets():
    """The config file that inspired this: a raw sk-… token sat in
    api_key_env for months, silently failing os.getenv.  Load must fail
    loudly instead."""
    import pytest

    from llm_redactor.config import load_config

    # default + valid names load fine (covered elsewhere); a secret-shaped
    # value raises with a message that names the field.
    cfg_text = "cloud_target:\n  api_key_env: sk-PASTED-SECRET-NOT-REAL\n"
    import pathlib
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(cfg_text)
        p = pathlib.Path(fh.name)
    try:
        with pytest.raises(ValueError, match="api_key_env"):
            load_config(p)
    finally:
        p.unlink(missing_ok=True)
