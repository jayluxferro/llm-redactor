"""Deterministic rule-based validation of detected spans.

Drop-in replacement for the Ollama validator (``llm_validator.validate_spans``)
selected via ``pipeline.llm_validation.backend: "rules"``. Instead of asking a
local LLM whether a span is real, each span's *kind* is looked up in ``RULES``
and the span's text is checked with pure arithmetic/shape rules (checksums,
digit counts, structural constraints). No local model, no network, no
nondeterminism — and microseconds instead of seconds.

Deliberate differences from the model validator:

- Regex-sourced spans are validated too. ``validate_spans`` auto-keeps
  everything with ``source == "regex"``, which meant a regex ``credit_card``
  match with a failing Luhn checksum was always redacted and a regex ``iban``
  typo was always redacted. Those are exactly the false positives checksum
  rules catch for free.
- Keep bias matches the model validator's contract: a kind with no rule is
  kept (same as a missing/KEEP verdict), and a rule that raises keeps the span
  (fail-open, per-span). We validate *shape*, never *context* — a real-looking
  card number inside a sentence still passes.

Intentionally NOT ruled (documented so gaps don't look like oversights):

- ``url`` / ``ip_v4`` / ``ip_v6`` / ``hostname_internal`` — the detecting
  regexes already enforce shape; a second shape check adds nothing.
- ``person`` / ``location`` / ``nationality`` / ``date_time`` / ``org``-style
  NER kinds — there is no checksum for a name. Filtering these is the one job
  the local LLM does that rules cannot; rules mode therefore keeps them all
  and relies on the orchestrator's existing false-positive suppression.
- ``bearer_token`` / ``basic_auth`` / ``password`` / ``secret_assignment`` —
  opaque values whose regex already encodes the length floor; dropping
  aggressively here risks leaking real credentials.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .types import Span

# A validator takes the span's matched text and answers "is this a real,
# well-formed instance of its kind?" (True = keep, False = drop).
RULES: dict[str, Callable[[str], bool]] = {}

# Base64url segments (JWT). The signature may carry unpadded-alphabet chars
# only; ``=`` padding is tolerated because some issuers still emit it.
_B64URL_SEG = re.compile(r"^[A-Za-z0-9_\-]+=*$")

# Trailing phone-extension marker ("ext.", "extension", "x") and its digits.
# Only the NER ``phone`` kind can carry one — the phone_us/phone_intl
# regexes use [-.\s] separators and structurally cannot match "ext".
_EXT_SUFFIX = re.compile(r"(?i)(?:ext(?:ension)?|x)\.?\s*\d{1,6}$")


def _digits(text: str) -> str:
    """Strip every separator, keeping digits only."""
    return "".join(c for c in text if c.isdigit())


def _luhn(digits: str) -> bool:
    """Luhn checksum over a digit string (ISO/IEC 7812-1)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        # Double every second digit counting from the rightmost.
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _credit_card(text: str) -> bool:
    digits = _digits(text)
    return 13 <= len(digits) <= 19 and _luhn(digits)


def _iban(text: str) -> bool:
    """ISO 13616 mod-97 check: move the leading country+check digits to the
    end, map letters to 10-35, and require the whole number ≡ 1 (mod 97)."""
    s = text.replace(" ", "").replace("-", "").upper()
    if len(s) < 15 or len(s) > 34 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    value = 0
    for ch in rearranged:
        if ch.isdigit():
            value = value * 10 + int(ch)
        elif "A" <= ch <= "Z":
            value = value * 100 + (ord(ch) - ord("A") + 10)
        else:
            return False
        # Keep the running modulus small — same result as one big mod at the end.
        value %= 97
    return value % 97 == 1


def _ssn(text: str) -> bool:
    digits = _digits(text)
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    # Social Security Administration allocation rules.
    if area in (0, 666) or area >= 900:
        return False
    return group != 0 and serial != 0


def _email(text: str) -> bool:
    if text.count("@") != 1:
        return False
    local, domain = text.split("@")
    if not local or not domain or "." not in domain:
        return False
    for part in (local, domain):
        if part.startswith(".") or part.endswith(".") or ".." in part:
            return False
    return True


def _phone_us(text: str) -> bool:
    digits = _digits(text)
    return len(digits) == 10 or (len(digits) == 11 and digits.startswith("1"))


def _phone_intl(text: str) -> bool:
    stripped = text.strip()
    if not (stripped.startswith("+") or stripped.startswith("00")):
        return False
    return 8 <= len(_digits(text)) <= 15


def _phone(text: str) -> bool:
    # NER ``phone`` spans legitimately lack an international prefix (Presidio
    # flags US-style "(415) 555-2671" too), so only the digit-count sanity
    # check applies here. Dropping prefix-less phones would leak them — same
    # for extensions: "+1 415 555 2671 ext. 90210" is a real phone whose
    # digit count crosses the E.164 ceiling only because of the extension,
    # so the suffix is excluded from the count before the sanity check.
    without_ext = _EXT_SUFFIX.sub("", text.strip())
    return 8 <= len(_digits(without_ext)) <= 15


def _jwt(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 3:
        return False
    return all(part and _B64URL_SEG.match(part) for part in parts)


def _key_like(text: str) -> bool:
    """Shape floor shared by generic and vendor/cloud key kinds: long enough
    to be a credential, mostly alphanumeric, never containing whitespace
    (whitespace means we matched prose, not a key)."""
    if any(c.isspace() for c in text):
        return False
    if len(text) < 20:
        return False
    return sum(1 for c in text if c.isalnum()) >= 15


def _register(kinds: tuple[str, ...], rule: Callable[[str], bool]) -> None:
    for kind in kinds:
        RULES[kind] = rule


_register(("credit_card",), _credit_card)
_register(("iban",), _iban)
_register(("ssn",), _ssn)
_register(("email",), _email)
_register(("phone_us",), _phone_us)
_register(("phone_intl",), _phone_intl)
_register(("phone",), _phone)
_register(("jwt",), _jwt)
_register(("generic_api_key",), _key_like)
_register(
    (
        "aws_access_key",
        "aws_secret_key",
        "aws_session_token",
        "gcp_api_key",
        "gcp_service_account",
        "azure_storage_key",
        "azure_connection_string",
        "openai_api_key",
        "anthropic_api_key",
        "github_token",
        "gitlab_token",
        "slack_token",
        "slack_webhook",
        "stripe_key",
        "twilio_key",
        "sendgrid_key",
        "mailgun_key",
        "npm_token",
        "pypi_token",
        "heroku_api_key",
    ),
    _key_like,
)


def validate_spans_rules(spans: list[Span]) -> list[Span]:
    """Filter *spans* with the deterministic per-kind rules.

    Keeps spans whose kind has no rule (mirroring the model validator's
    missing-verdict-⇒-keep contract) and keeps any span whose rule raises —
    a buggy rule must never widen what leaves the proxy unredacted.
    """
    kept: list[Span] = []
    for span in spans:
        rule = RULES.get(span.kind)
        if rule is None:
            kept.append(span)
            continue
        try:
            if rule(span.text):
                kept.append(span)
        except Exception:  # per-span fail-open: a broken rule must not unredact
            kept.append(span)
    return kept
