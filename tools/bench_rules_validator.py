#!/usr/bin/env python
"""Benchmark the span-validator backends over a fixed labeled corpus.

Three arms score the SAME corpus of labeled spans (``valid`` or ``invalid``
instances of every ruled kind, plus rule-less NER kinds):

- ``none``  — no validation pass (detection output as-is).
- ``rules`` — ``detect.rules_validator.validate_spans_rules`` (deterministic).
- ``model`` — ``detect.llm_validator.validate_spans`` via Ollama (optional;
  pass an endpoint as argv[1], model as argv[2]).

Metrics per arm: share of labeled-invalid spans DROPPED (higher = catches more
false positives), share of labeled-valid spans KEPT (higher = fewer privacy
leaks), and per-text wall time of the validation step. Detection cost is
identical across arms and therefore excluded.

Usage:
    uv run python tools/bench_rules_validator.py [ollama_endpoint] [model]
    python tools/bench_rules_validator.py http://127.0.0.1:11435 llama3.2:1b

The corpus labels are self-checked against independent Luhn/mod-97 reference
implementations at startup, so a mislabeled card/IBAN fails loudly instead of
silently skewing the precision numbers.
"""

from __future__ import annotations

import asyncio
import base64
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_redactor.detect.llm_validator import validate_spans  # noqa: E402
from llm_redactor.detect.rules_validator import RULES, validate_spans_rules  # noqa: E402
from llm_redactor.detect.types import Span  # noqa: E402

DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:1b"

# ---------------------------------------------------------------------------
# Reference checksums (independent copies of the algorithms — reusing the
# module under test would make the corpus self-labeling circular).
# ---------------------------------------------------------------------------


def _ref_luhn(digits: str) -> bool:
    total = 0
    for pos, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if pos % 2 else 1)
        total += (d - 9) if d > 9 else d
    return total % 10 == 0


def _luhn_check_digit(payload: str) -> str:
    total = 0
    for pos, ch in enumerate(reversed(payload)):  # check slot itself is pos -1 ⇒ shift
        d = int(ch) * (2 if pos % 2 == 0 else 1)
        total += (d - 9) if d > 9 else d
    return str((10 - total % 10) % 10)


def _make_card(prefix: str, length: int = 16) -> str:
    body = (prefix + "1" * length)[: length - 1]
    return body + _luhn_check_digit(body)


def _ref_iban_mod97(iban: str) -> int:
    s = iban.replace(" ", "").upper()
    num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(num) % 97


# ---------------------------------------------------------------------------
# Labeled corpus: (kind, value, valid). ~130 spans over every ruled kind plus
# the rule-less NER kinds. Invalid entries are near-misses of their valid
# twins (one flipped digit, one dropped segment) — exactly the false positives
# a validator is supposed to catch.
# ---------------------------------------------------------------------------

Item = tuple[str, str, bool]


def _jwt(parts: int, payload: str = "sub") -> str:
    def seg(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    header = seg('{"alg":"HS256"}')
    body = seg(payload + "=1")
    if parts == 3:
        return f"{header}.{body}.{seg('signature')}"
    return f"{header}.{body}"


def _corpus() -> list[Item]:
    items: list[Item] = []

    # credit_card — kept regex-source (as the regex detector emits them), so
    # the model arm auto-keeps these by design; checksum rules are what
    # finally catch the bad ones.
    valid_cards = [
        "4111111111111111",
        "4242424242424242",
        "378282246310005",
        "6011111111111117",
        _make_card("4532", 16),
        _make_card("5500", 16),
        _make_card("6011", 16),
        _make_card("5105", 16),
        _make_card("4012", 16),
    ]
    for card in valid_cards:
        assert _ref_luhn(card), f"corpus bug: {card} labeled valid fails Luhn"
        items.append(("credit_card", card, True))
        broken = card[:-1] + str((int(card[-1]) + 1) % 10)
        assert not _ref_luhn(broken), f"corpus bug: {broken} labeled invalid passes Luhn"
        items.append(("credit_card", broken, False))
    items.append(("credit_card", "4111 1111 1111 1111", True))  # spaced, still Luhn-valid
    items.append(("credit_card", "1234567890123456", False))  # sequential junk

    # iban — NER-source today; both validators see it.
    valid_ibans = [
        "GB82WEST12345698765432",
        "DE89370400440532013000",
        "NL91ABNA0417164300",
        "FR1420041010050500013M02606",
        "IT60X0542811101000000123456",
    ]
    for iban in valid_ibans:
        assert _ref_iban_mod97(iban) == 1, f"corpus bug: {iban} labeled valid fails mod-97"
        items.append(("iban", iban, True))
        broken = iban[:-1] + str((int(iban[-1]) + 1) % 10)
        assert _ref_iban_mod97(broken) != 1, f"corpus bug: {broken} labeled invalid passes"
        items.append(("iban", broken, False))
    items.append(("iban", "GB82 WEST 1234 5698 7654 32", True))

    # ssn — NER-source in production (Presidio US_SSN), so the model arm
    # gets a say on these.
    for ssn in (
        "123-45-6789",
        "214-88-7490",
        "536-90-4399",
        "123456789",
        "856-25-5093",
        "602-31-8874",
    ):
        items.append(("ssn", ssn, True))
    for ssn in (
        "000-45-6789",
        "666-45-6789",
        "900-45-6789",
        "990-45-6789",
        "123-00-6789",
        "123-45-0000",
    ):
        items.append(("ssn", ssn, False))

    # email — NER-source in production (Presidio EMAIL_ADDRESS).
    for mail in (
        "alice@example.com",
        "bob.smith@company.co.uk",
        "maria+tag@garcia.dev",
        "support@llm-redactor.org",
        "kwame@presidio.ai",
    ):
        items.append(("email", mail, True))
    for mail in (
        "a..b@example.com",
        ".dot@example.com",
        "dot@example.com.",
        "alice@localhost",
        "a@b..example.com",
    ):
        items.append(("email", mail, False))

    # phones
    for phone in (
        "(415) 555-2671",
        "212-664-7665",
        "1-800-555-0199",
        "415.555.2671",
        "1 (415) 555-2671",
    ):
        items.append(("phone_us", phone, True))
    for phone in ("415-555-267", "41555526712"):
        items.append(("phone_us", phone, False))
    for phone in ("+44 20 7946 0958", "+81-3-1234-5678", "0041 44 689 11 22", "+34 91 123 45 67"):
        items.append(("phone_intl", phone, True))
    for phone in ("20 7946 0958", "+44 20 9"):
        items.append(("phone_intl", phone, False))
    for phone in ("(650) 253-0000", "+1 650 253 0000", "555-867-5309"):
        items.append(("phone", phone, True))
    for phone in ("555", "867-5309"):
        items.append(("phone", phone, False))

    # jwt
    items.append(("jwt", _jwt(3), True))
    items.append(("jwt", _jwt(3, "invoice"), True))
    items.append(("jwt", _jwt(3, "session"), True))
    items.append(("jwt", _jwt(2), False))
    items.append(("jwt", "a.b.", False))  # empty signature segment

    # generic + vendor/cloud keys (all share the key-shaped floor)
    keys_valid = [
        ("generic_api_key", "j9K2mN4pQ7rS1tU3vW5xYz"),
        ("generic_api_key", "9f86d081884c7d659a2feaa0c55ad015"),
        ("generic_api_key", "f00d4b2cafebabe04517"),
        ("generic_api_key", "Zx9-Wq8_Pe7.Kd6/Jc5=Ib4a"),
        ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        ("aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("gcp_api_key", "AIzaSyA" + "1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuVwxyZ"),
        ("azure_storage_key", "a" + "A1+/=" * 17 + "aA"),
        ("openai_api_key", "sk-proj-4f8a2b6c8d0e2f4a6b8d0e2f4a6b8d0e2f4a"),
        ("openai_api_key", "sk-9x8y7z6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c"),
        ("anthropic_api_key", "sk-ant-api03-x9y8z7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2"),
        ("github_token", "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        ("gitlab_token", "glpat-" + "a1B2c3D4e5F6g7H8i9J0"),
        ("slack_token", "xoxb-not-a-real-token-A1b2C3d4E5f6G7h8I9jK1l2M3"),  # fake
        ("slack_webhook", "https://hooks.slack.com/services/T024B1B2C3/B4D5E6F7G8/a1b2c3d4e5f6"),
        ("stripe_key", "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"),
        ("twilio_key", "SK" + "0123456789abcdef0123456789abcdef"),
        ("sendgrid_key", "SG.a1B2c3D4e5f6G7h8I9j0K1.l2M3n4O5p6Q7r8S9t0U1v2W3x4"),
        ("mailgun_key", "key-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"),
        ("npm_token", "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2M3n4O5p6Q7r8"),
        ("pypi_token", "pypi-AgEIcHlwaS5vcmc" + "CJTVjZmM3NjRlLWU0YTItNGY4ZC1i" * 1 + "abcd"),
        ("heroku_api_key", "f2c1a345-6d7e-4f8a-9b0c-1d2e3f4a5b6c"),
    ]
    items.extend((kind, value, True) for kind, value in keys_valid)
    keys_invalid = [
        ("generic_api_key", "short1"),
        ("generic_api_key", "--------------------"),
        ("openai_api_key", "sk-proj-2short"),
        ("github_token", "ghp_123456"),
        ("aws_access_key", "AKIA123"),
        ("stripe_key", "sk_live_2short"),
        ("gitlab_token", "glpat-2short"),
        ("twilio_key", "SKabcdef"),
    ]
    items.extend((kind, value, False) for kind, value in keys_invalid)

    # Rule-less kinds — must pass through every arm untouched.
    for kind, value in (
        ("person", "Maria Garcia-Lopez"),
        ("person", "Kwame Mensah"),
        ("person", "Adaeze Okafor"),
        ("person", "Dr. Yaa Amponsah"),
        ("location", "Kumasi"),
        ("location", "Accra Central"),
        ("location", "Takoradi harbour district"),
        ("nationality", "Ghanaian"),
        ("nationality", "Nigerian"),
        ("date_time", "next Tuesday"),
        ("date_time", "March 3rd, 2026"),
        ("date_time", "last Friday evening"),
        ("url", "https://example.com/pay/quote"),
        ("ip_v4", "192.168.13.37"),
    ):
        items.append((kind, value, True))

    return items


def _self_check(items: list[Item]) -> None:
    """Fail loudly on a corpus label that contradicts the rule set.

    The checksum kinds are already guarded by the independent reference
    implementations above; this sweeps the shape rules (email/phone/key) so a
    typo in a label shows up as an error instead of silently skewing one arm.
    """
    for kind, value, valid in items:
        rule = RULES.get(kind)
        if rule is None:
            continue
        assert rule(value) is valid, (
            f"corpus bug: {kind}={value!r} labeled valid={valid} but rule disagrees"
        )


# Presidio detects these kinds (iban/ssn/email/phone via its recognizers), so
# in production they reach the validator as NER spans; the rest of the ruled
# kinds are regex-only.
NER_SOURCE_KINDS = {
    "iban",
    "ssn",
    "email",
    "phone",
    "person",
    "location",
    "nationality",
    "date_time",
}

TEMPLATES = {
    "credit_card": "the card on file is {v}",
    "iban": "wire it to account {v}",
    "ssn": "her SSN is {v}",
    "email": "reach me at {v} please",
    "phone_us": "call (415) area office {v} today",
    "phone_intl": "the London line is {v}",
    "phone": "phone: {v}",
    "jwt": "auth header Bearer {v}",
    "generic_api_key": "with api_key {v} configured",
    "aws_access_key": "access key {v} attached",
    "aws_secret_key": "secret key {v} rotated",
    "gcp_api_key": "maps key {v} quota",
    "azure_storage_key": "account key {v} saved",
    "openai_api_key": "the sk key {v} works",
    "anthropic_api_key": "the ant key {v} works",
    "github_token": "the ghp token {v} expired",
    "gitlab_token": "the glpat token {v} expired",
    "slack_token": "the xoxb token {v} rotated",
    "slack_webhook": "post alerts to {v} nightly",
    "stripe_key": "the stripe sk key {v} live",
    "twilio_key": "the twilio sid {v} assigned",
    "sendgrid_key": "the SG key {v} sending",
    "mailgun_key": "the mailgun key {v} sending",
    "npm_token": "the npm token {v} published",
    "pypi_token": "the pypi token {v} uploaded",
    "heroku_api_key": "heroku key {v} deployed",
    "person": "contact {v} about it",
    "location": "based in {v} nearby",
    "nationality": "a {v} citizen",
    "date_time": "due {v} sharp",
    "url": "see {v} for details",
    "ip_v4": "host at {v} internal",
}


@dataclass
class Text:
    body: str
    spans: list[Span]  # parallel to labels
    labels: list[bool]  # True = valid instance (must be kept)


def _build_texts(items: list[Item], per_text: int = 5) -> list[Text]:
    texts: list[Text] = []
    for chunk_start in range(0, len(items), per_text):
        chunk = items[chunk_start : chunk_start + per_text]
        body_parts: list[str] = []
        spans: list[Span] = []
        labels: list[bool] = []
        for idx, (kind, value, valid) in enumerate(chunk):
            sentence = TEMPLATES[kind].format(v=value)
            offset = sum(len(p) + 1 for p in body_parts)
            pos = sentence.find(value)
            assert pos >= 0, f"template for {kind} must embed the value verbatim"
            body_parts.append(sentence)
            spans.append(
                Span(
                    start=offset + pos,
                    end=offset + pos + len(value),
                    kind=kind,
                    confidence=1.0 if kind not in NER_SOURCE_KINDS else 0.85,
                    text=value,
                    source="ner" if kind in NER_SOURCE_KINDS else "regex",
                )
            )
            labels.append(valid)
        texts.append(Text(body=" ".join(body_parts), spans=spans, labels=labels))
    return texts


# ---------------------------------------------------------------------------
# Arms
# ---------------------------------------------------------------------------


@dataclass
class Score:
    dropped_invalid: int
    total_invalid: int
    lost_valid: int
    total_valid: int
    # Invalid-drop split by span source: the model arm auto-keeps regex-source
    # spans, so this is where the two backends fundamentally differ.
    dropped_invalid_regex: int = 0
    total_invalid_regex: int = 0
    dropped_invalid_ner: int = 0
    total_invalid_ner: int = 0


def _score(arm_kept: list[list[Span]], texts: list[Text]) -> Score:
    score = Score(0, 0, 0, 0)
    for kept, text in zip(arm_kept, texts, strict=True):
        kept_ids = {id(s) for s in kept}
        for span, valid in zip(text.spans, text.labels, strict=True):
            if valid:
                score.total_valid += 1
                score.lost_valid += id(span) not in kept_ids
            else:
                score.total_invalid += 1
                dropped = id(span) not in kept_ids
                score.dropped_invalid += dropped
                if span.source == "regex":
                    score.total_invalid_regex += 1
                    score.dropped_invalid_regex += dropped
                else:
                    score.total_invalid_ner += 1
                    score.dropped_invalid_ner += dropped
    return score


def _pct(num: int, den: int) -> float:
    return 100.0 if den == 0 and num == 0 else (num / den * 100 if den else 0.0)


def _bar(pct: float, width: int = 12) -> str:
    filled = round(pct / 100 * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


async def _run_model_arm(
    texts: list[Text], endpoint: str, model: str
) -> tuple[list[list[Span]], list[float]]:
    kept: list[list[Span]] = []
    ms: list[float] = []
    for text in texts:
        t0 = time.perf_counter()
        kept.append(await validate_spans(text.body, text.spans, endpoint=endpoint, model=model))
        ms.append((time.perf_counter() - t0) * 1000)
    return kept, ms


def _fmt_pct(num: int, den: int) -> str:
    return "n/a" if den == 0 else f"{num / den * 100:5.1f}%"


def _fmt_ms(values: list[float]) -> str:
    if not values:
        return "n/a"
    p95 = statistics.quantiles(values, n=20)[-1] if len(values) > 1 else values[0]
    return f"p50 {statistics.median(values):8.2f}  p95 {p95:8.2f}"


async def main() -> int:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ENDPOINT
    model = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL

    items = _corpus()
    _self_check(items)
    texts = _build_texts(items)
    span_count = sum(len(t.spans) for t in texts)
    invalid_count = sum(1 for t in texts for label in t.labels if not label)
    print(f"corpus: {span_count} labeled spans ({invalid_count} invalid) in {len(texts)} texts")
    print()

    arms: dict[str, tuple[list[list[Span]], list[float]]] = {}
    arms["none"] = ([list(t.spans) for t in texts], [0.0] * len(texts))

    t0 = time.perf_counter()
    arms["rules"] = ([validate_spans_rules(t.spans) for t in texts], [])
    rules_ms = (time.perf_counter() - t0) * 1000 / len(texts)
    arms["rules"] = (arms["rules"][0], [rules_ms] * len(texts))

    model_available = True
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            (await client.get(f"{endpoint.rstrip('/')}/api/tags")).raise_for_status()
    except Exception as exc:
        model_available = False
        print(f"model arm unavailable ({type(exc).__name__} reaching {endpoint}); skipped\n")

    if model_available:
        arms["model"] = await _run_model_arm(texts, endpoint, model)

    label = {
        "none": "none (detect only)",
        "rules": "rules",
        "model": f"model ({model} @ {endpoint})",
    }
    print(f"{'arm':<46} {'inv-drop':>16} {'val-keep':>16}   validation ms/text")
    for name in ("none", "rules", "model"):
        if name not in arms:
            print(f"{label[name]:<46} {'unavailable':>16}")
            continue
        kept, ms = arms[name]
        score = _score(kept, texts)
        drop_pct = _pct(score.dropped_invalid, score.total_invalid)
        keep_pct = _pct(score.total_valid - score.lost_valid, score.total_valid)
        ms_str = _fmt_ms(ms)
        print(
            f"{label[name]:<46} "
            f"{_fmt_pct(score.dropped_invalid, score.total_invalid):>8} {_bar(drop_pct)} "
            f"{_fmt_pct(score.total_valid - score.lost_valid, score.total_valid):>8} "
            f"{_bar(keep_pct)}   {ms_str}"
        )
        if score.total_invalid and score.total_invalid_regex and score.total_invalid_ner:
            print(
                f"    invalid-drop by source: "
                f"regex {_fmt_pct(score.dropped_invalid_regex, score.total_invalid_regex)} "
                f"({score.dropped_invalid_regex}/{score.total_invalid_regex})  "
                f"ner {_fmt_pct(score.dropped_invalid_ner, score.total_invalid_ner)} "
                f"({score.dropped_invalid_ner}/{score.total_invalid_ner})"
            )

    print()
    rules_score = _score(arms["rules"][0], texts)
    ok = rules_score.dropped_invalid == rules_score.total_invalid and rules_score.lost_valid == 0
    print(f"rules pass (invalid-drop 100% AND valid-keep 100%): {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
