"""Adversarial edge cases for the deterministic rules backend.

Complements test_rules_validator.py with inputs that break naive
implementations: unicode digits (isdigit()/int() divergence), extension
suffixes on NER phone spans, batch-level isolation of a raising rule, and
checksum rules cross-checked against independent reference implementations
(including seeded random IBAN fuzzing).

Safety direction reminder used throughout: a rule returning False *drops*
the span, i.e. the text leaves the proxy unredacted — that is the leak
direction. Fail-open (rule raises → keep) and no-rule (keep) are the safe
directions, so tests distinguish "wrongly dropped" (bug) from "wrongly
kept" (over-redaction, safe but pinned where surprising).
"""

from __future__ import annotations

import random
import string
import uuid
from unittest.mock import patch

import pytest

from llm_redactor.detect.rules_validator import RULES, validate_spans_rules
from llm_redactor.detect.types import Span
from llm_redactor.pipeline.option_b import OptionBPipeline


def _span(kind: str, text: str, source: str = "regex", confidence: float = 1.0) -> Span:
    return Span(start=0, end=len(text), kind=kind, confidence=confidence, text=text, source=source)


# --- reference implementations (independent of the module under test) --------


def _ref_luhn(digits: str) -> bool:
    total = 0
    for pos, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if pos % 2 else 1)
        total += (d - 9) if d > 9 else d
    return total % 10 == 0


def _ref_iban_valid(iban: str) -> bool:
    """ISO 13616 shape + mod-97, written independently of rules_validator."""
    s = iban.replace(" ", "").replace("-", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(num) % 97 == 1


# --- credit_card -------------------------------------------------------------


def test_credit_card_all_zeros_luhn_passes_but_is_unreachable():
    """Luhn has no all-zero exclusion (sum 0 ≡ 0 mod 10), so the rule keeps
    16 zeros. Not a leak: the detecting regex requires a 4/5[1-5]/3[47]/6
    prefix, so an all-zero "card" never becomes a span, and keep = redacted
    anyway. Pinned so the Luhn property doesn't read as an oversight."""
    assert _ref_luhn("0" * 16) is True
    assert RULES["credit_card"]("0" * 16) is True


def test_credit_card_13_digit_visa_and_mixed_separators_kept():
    assert _ref_luhn("4222222222222") is True
    assert RULES["credit_card"]("4222222222222") is True  # 13-digit Visa
    assert RULES["credit_card"]("4532 0151-1283 0366") is True  # mixed seps
    assert RULES["credit_card"]("3782 8224 6310 005") is True  # spaced Amex


def test_credit_card_arabic_indic_digits_kept():
    """int() accepts every Unicode Nd digit, so a card typed in
    Arabic-Indic numerals Luhn-checks against the same values."""
    assert RULES["credit_card"]("٤" + "١" * 15) is True  # bare: 4111111111111111
    assert RULES["credit_card"]("٤" + "١" * 14) is False  # 15 bare digits: too short
    assert RULES["credit_card"]("4111 1111 1111 1111") is True  # narrow no-break spaces


def test_credit_card_superscript_digit_fails_open_kept():
    """'²'.isdigit() is True but int('²') raises — the rule explodes on such
    input and the per-span fail-open keeps the span (redacted). Pinned to
    prove the crash path is input-reachable and fails SAFE, not closed."""
    spans = [_span("credit_card", "4111²111111111111")]
    assert validate_spans_rules(spans) == spans


# --- iban --------------------------------------------------------------------


def test_iban_lowercase_and_dashes_kept():
    assert RULES["iban"]("gb82 west 1234 5698 7654 32") is True
    assert RULES["iban"]("gb82-west-1234-5698-7654-32") is True


def test_iban_structural_rejections():
    assert RULES["iban"]("GBWEST12345698765432") is False  # check digits missing
    assert RULES["iban"]("GB82 WEST") is False  # far too short
    assert RULES["iban"]("GBX2WEST12345698765432") is False  # check digits not numeric
    assert RULES["iban"]("GB82WEST12345698765431") is False  # one-digit flip
    assert RULES["iban"]("GB82WEST1234569876543") is False  # truncated
    # Letters in the BBAN are legal ISO 13616 (Malta vector) — must keep.
    assert _ref_iban_valid("MT84MALT011000012345MTLCAST001S") is True
    assert RULES["iban"]("MT84MALT011000012345MTLCAST001S") is True
    # 15-char floor: Norwegian IBANs are exactly 15.
    assert RULES["iban"]("NO9386011117947") is True


def test_iban_matches_independent_reference_under_fuzz():
    """Seeded fuzz: for every string with a plausible country prefix, the
    rule's verdict must equal the textbook big-int mod-97 verdict."""
    rng = random.Random(20260917)
    for _ in range(3000):
        length = rng.randint(15, 34)
        country = "".join(rng.choice(string.ascii_uppercase) for _ in range(2))
        body = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(length))
        s = (country + "00" + body)[:34]
        assert RULES["iban"](s) is _ref_iban_valid(s), f"disagreement on {s!r}"


def test_iban_catches_single_char_mutations_modulo_known_collisions():
    """Sweep every single-character mutation of a valid IBAN. mod-97 misses a
    residue collision ~0.4% of the time by design; assert the observed rate
    stays at that level (767/770 for this vector) so a regression to a
    weaker check (length-only, prefix-only) cannot slip through."""
    base = "GB82WEST12345698765432"
    caught = total = 0
    for pos in range(len(base)):
        for repl in string.ascii_uppercase + string.digits:
            if repl == base[pos]:
                continue
            total += 1
            if not RULES["iban"](base[:pos] + repl + base[pos + 1 :]):
                caught += 1
    assert caught >= total * 0.99


# --- ssn ---------------------------------------------------------------------


def test_ssn_woolworth_fake_is_shape_valid_and_kept():
    """078-05-1120 passes every SSA allocation rule (area 078 is allocated,
    group/serial nonzero) even though it was famously printed on wallet
    cards. Rules validate shape, never issuance — the docstring's contract."""
    assert RULES["ssn"]("078-05-1120") is True


# --- email -------------------------------------------------------------------


def test_email_odd_but_overredaction_safe_shapes_kept():
    """All kept (= redacted). 'alice@127.0.0.1' has a dotted numeric domain;
    the space and unicode forms are NER-plausible. Over-keeping is the safe
    direction, pinned so nobody 'tightens' this into a leak later."""
    for text in ("alice@127.0.0.1", "alice @example.com", "ünicode@例え.com"):
        assert RULES["email"](text) is True, text


def test_email_unambiguous_junk_dropped():
    assert RULES["email"]("a@x") is False  # no dot in domain
    assert RULES["email"]("a@localhost") is False
    assert RULES["email"]("") is False


# --- jwt ---------------------------------------------------------------------


def test_jwt_segment_shape_edges():
    assert RULES["jwt"]("a.b") is False  # two segments
    assert RULES["jwt"]("a.b.c.d") is False  # four segments
    assert RULES["jwt"]("..") is False  # empty segments
    assert RULES["jwt"]("a$.b.c") is False  # invalid base64url char
    assert RULES["jwt"]("a.b=c.d") is False  # padding must trail, not lead
    assert RULES["jwt"]("a.b.") is False  # empty signature
    assert RULES["jwt"]("abc-DEF_123.ghi-JKL_456.mno") is True  # unpadded b64url


# --- phones ------------------------------------------------------------------


def test_phone_us_leading_two_and_nine_digits_dropped():
    assert RULES["phone_us"]("4155552671") is True
    assert RULES["phone_us"]("24155552671") is False  # 11 digits, leading 2
    assert RULES["phone_us"]("415555267") is False  # 9 digits


def test_phone_intl_length_ceiling_and_prefix_requirement():
    assert RULES["phone_intl"]("00442079460958") is True
    assert RULES["phone_intl"]("442079460958") is False  # no +/00 prefix
    assert RULES["phone_intl"]("+44207946095812345") is False  # 17 digits


def test_phone_ner_kind_survives_extension_suffix():
    """Extensions are not part of the E.164 number. A NER phone span like
    '+1 415 555 2671 extension 90210' crosses the 15-digit ceiling only
    because of the extension; dropping it leaks a real phone number (the
    leak direction). The extension must be excluded from the count."""
    assert RULES["phone"]("+1 415 555 2671 extension 90210") is True
    assert RULES["phone"]("+1 415 555 2671 ext. 1234") is True
    assert RULES["phone"]("+1-415-555-2671x1234") is True
    assert RULES["phone"]("+44 20 7946 0958 x 99") is True
    # Sanity: the extension change must not resurrect the short-number drop.
    assert RULES["phone"]("555") is False


# --- key floor ---------------------------------------------------------------


def test_key_floor_boundaries():
    assert RULES["generic_api_key"]("a" * 17) is False
    assert RULES["generic_api_key"]("a" * 19) is False
    assert RULES["generic_api_key"]("a" * 20) is True
    assert RULES["generic_api_key"]("a\tb cde fghij klmno") is False  # whitespace
    # Unicode letters count as alphanumeric: kept (= redacted), safe direction.
    assert RULES["generic_api_key"]("ΚΛΜΝΞΟΠQRSTUVWXYZ123") is True


# --- batch semantics ---------------------------------------------------------


def test_empty_batch_and_empty_text_spans():
    assert validate_spans_rules([]) == []
    assert validate_spans_rules([_span("email", "")]) == []  # no rule pass, dropped
    empty = _span("person", "")
    assert validate_spans_rules([empty]) == [empty]  # no rule → kept unchanged


def test_raising_rule_isolated_to_its_own_span():
    """One raising rule must keep *its* span (fail-open) AND leave every
    other span in the batch fully validated — the raising span comes first
    so a loop-level try/except (instead of per-span) would skip the rest."""

    def boom(_text: str) -> bool:
        raise RuntimeError("buggy rule")

    bad_luhn = _span("credit_card", "4111111111111112")
    good_email = _span("email", "a..b@example.com")  # double dot → must drop
    with patch.dict(RULES, {"credit_card": boom}):
        kept = validate_spans_rules([bad_luhn, good_email])
    assert kept == [bad_luhn]


# --- end-to-end: mixed text, rules backend, zero Ollama calls ----------------


@pytest.mark.asyncio
async def test_option_b_rules_backend_mixed_text_zero_ollama_calls():
    """Valid card + bad-Luhn card + person name in one text: rules backend
    drops only the bad card, keeps the rest, and never reaches Ollama."""

    async def _no_ollama(*_args: object, **_kwargs: object) -> list[Span]:
        raise AssertionError("rules backend must not call the Ollama validator")

    text = (
        f"Receipt {uuid.uuid4().hex[:8]}: declined card 4111111111111112, "
        f"charged 4532015112830366 to Maria Garcia-Lopez (maria@example.com)."
    )
    from llm_redactor.config import Config

    config = Config()
    config.pipeline.llm_validation.enabled = True
    config.pipeline.llm_validation.backend = "rules"
    pipeline = OptionBPipeline(config=config, use_ner=True)

    with patch(
        "llm_redactor.detect.llm_validator.validate_spans",
        side_effect=_no_ollama,
    ):
        spans = await pipeline.detect_spans(text)

    by_text = {(s.kind, s.text) for s in spans}
    assert ("credit_card", "4111111111111112") not in by_text  # bad Luhn dropped
    assert ("credit_card", "4532015112830366") in by_text  # valid card kept
    assert ("email", "maria@example.com") in by_text  # valid email kept
    assert any(kind == "person" for kind, _ in by_text)  # NER span kept (no rule)
