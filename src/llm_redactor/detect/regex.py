"""Regex-based detector for secrets and structured PII."""

from __future__ import annotations

import re
from collections.abc import Callable

from . import checksums
from .types import Span

# ---------------------------------------------------------------------------
# Pattern families — comprehensive regex detection for PII and secrets.
#
# Sources: gitleaks rules, trufflehog patterns, detect-secrets,
# OWASP secret patterns, AWS/GCP/Azure documentation.
#
# Extend via config's extend_patterns_file for org-specific patterns.
# ---------------------------------------------------------------------------

PATTERNS: dict[str, re.Pattern[str]] = {
    # ── PII ──────────────────────────────────────────────────────────────
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "phone_us": re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"),
    "phone_intl": re.compile(
        r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{1,4})?"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ip_v4": re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
    ),
    "ip_v6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    ),
    "credit_card": re.compile(
        # Visa, Mastercard, Amex, Discover (with optional separators)
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b"
    ),
    "employee_id": re.compile(r"\bEMP-\d{4,6}\b"),
    # Street addresses.  NER tags only the *city* in a mailing address, so the
    # street line and ZIP leaked; this anchor catches the whole address.
    # Number-first anchoring keeps the false-positive rate low.
    "address": re.compile(
        r"\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'\-]*\s+){0,4}"
        r"(?i:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|"
        r"Circle|Cir|Court|Ct|Way|Place|Pl|Terrace|Ter|Highway|Hwy|Parkway|"
        r"Pkwy|Square|Sq|Trail|Trl|Loop|Alley|Crescent|Cres|"
        r"Street|Avenue)\.?"
        r"(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|Bldg|Floor|Fl|#)\.?\s*[A-Za-z0-9\-]+)?"
        r"(?:\s*,\s*[A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+)*)?"
        r"(?:\s*,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?"
    ),
    # ── Government identifiers ────────────────────────────────────────────
    # Context-anchored: a bare "9 digits" or "2-7 digits" pattern is all
    # false positives, so the keyword carries the precision and the capture
    # group keeps only the identifier itself.
    "passport_number": re.compile(
        r"(?i)passport\s*(?:number|no\.?|#|id)?\s*[:=]?\s*([A-Z]{0,2}\d{7,9})\b"
    ),
    "ein": re.compile(
        r"(?i)\b(?:ein|employer\s+id(?:entification)?|tax\s+id|tin)\b\s*[:=#]?\s*(\d{2}-?\d{7})\b"
    ),
    "dob": re.compile(
        r"(?i)(?:date\s+of\s+birth|d\.?o\.?b\.?|birth\s*date|born(?:\s+on)?)"
        r"\s*[:=]?\s*(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})"
    ),
    # ── Financial: bank accounts & crypto wallets ─────────────────────────
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){3,8}\b"),
    "us_routing_number": re.compile(
        r"(?i)(?:routing|aba|rtn)\s*(?:number|no\.?|#)?\s*[:=]?\s*(\d{9})"
    ),
    "us_bank_account": re.compile(
        r"(?i)(?:account|acct)\s*(?:number|no\.?|#)\s*[:=]?\s*(\d{6,17})"
    ),
    # Wallet addresses are unrecoverable if leaked (transfers are final), so
    # they are treated as critical even though they are not "identity" data.
    "crypto_btc": re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "crypto_eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    # ── Medical identifiers (checksum-validated at detection time) ────────
    # Context-anchored AND keyword-inclusive on purpose.  A bare 10-digit NPI is
    # span-identical to a US phone number; a context-free (or value-only) match
    # loses the overlap merge to ``phone_us`` and the span is then categorised
    # ``contact`` instead of ``medical`` — a policy of ``categories: [medical]``
    # would filter it out and leak.  Spanning the keyword makes the span start
    # earlier than the phone match, so the medical label wins the merge (the
    # checksum still validates the digits inside it).
    "npi": re.compile(r"(?i)\bnpi\b\s*(?:number|no\.?|#|id)?\s*[:=]?\s*[12]\d{9}\b"),
    "dea_number": re.compile(r"\b[A-Za-z][A-Za-z]\d{7}\b"),
    # ── Network ───────────────────────────────────────────────────────────
    "mac_address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    # ── Passwords & secrets in assignments ────────────────────────────────
    "password": re.compile(
        r"(?i)(?:password|passwd|pwd|pass)[\s]*[=:]\s*"
        r"(?:\"([^\"\r\n]{4,})\"|'([^'\r\n]{4,})'|(\S{4,}))"
    ),
    "secret_assignment": re.compile(
        r"(?i)['\"]?(?:secret|token|credential|auth)['\"]?[\s]*[=:]\s*"
        r"['\"]?([A-Za-z0-9\-_.:+/=]{8,})['\"]?"
    ),
    "connection_string": re.compile(
        r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'\"]{10,}"
    ),
    # ── Cloud provider keys ───────────────────────────────────────────────
    # AWS
    "aws_access_key": re.compile(
        r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"
    ),
    "aws_secret_key": re.compile(
        r"(?i)['\"]?(?:aws)?[_\-]?(?:secret)?[_\-]?(?:access)?[_\-]?key['\"]?"
        # Allow the value to be separated from its key name, as in Terraform's
        # `variable "aws_secret_key" { default = "..." }` — the 40-char base64
        # value keeps this from matching prose.
        r"[^=]{0,40}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "aws_session_token": re.compile(
        r"(?i)aws[_\-]?session[_\-]?token[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"
    ),
    # GCP
    "gcp_service_account": re.compile(r"\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b"),
    "gcp_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    # Azure
    "azure_storage_key": re.compile(
        r"(?i)(?:account[_\-]?key|storage[_\-]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?"
    ),
    "azure_connection_string": re.compile(
        r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"
    ),
    # ── API keys by vendor ────────────────────────────────────────────────
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-(?:api03-)?[a-zA-Z0-9\-_]{20,}\b"),
    "github_token": re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"
        r"|\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}\b"
    ),
    "gitlab_token": re.compile(r"\bgl(?:pat|ptt|dt|rt|at)-[A-Za-z0-9\-_]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
    ),
    "stripe_key": re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    "twilio_key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{20,}\b"),
    "mailgun_key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "pypi_token": re.compile(r"\bpypi-[A-Za-z0-9\-_]{50,}\b"),
    # Require "heroku" context — bare UUID pattern matches too many false positives
    # (session IDs, request IDs, correlation IDs, etc.)
    "heroku_api_key": re.compile(
        r"(?i)heroku[_\-]?(?:api[_\-]?)?(?:key|token)[\s]*[=:\s]+['\"]?"
        r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?"
    ),
    "telegram_bot_token": re.compile(r"\b\d{5,12}:[A-Za-z0-9_-]{30,}\b"),
    "discord_token": re.compile(r"\bMTA[0-9A-Za-z_-]{20,}\b"),
    # ── Generic patterns ──────────────────────────────────────────────────
    "generic_api_key": re.compile(
        r"(?i)['\"]?(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"
        r"['\"]?[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.:+/=]{16,})['\"]?"
    ),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*"),
    "basic_auth": re.compile(r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b"),
    "private_key_pem": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:RSA |EC |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    "ssh_private_key": re.compile(
        r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
        re.DOTALL,
    ),
    "pgp_private_key": re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
        re.DOTALL,
    ),
    # ── Hostnames ─────────────────────────────────────────────────────────
    "hostname_internal": re.compile(
        r"\b[a-z][a-z0-9\-]+\.(?:internal|local|corp|lan|intranet|private|staging|dev)\b"
    ),
}


_custom_patterns: dict[str, re.Pattern[str]] = {}

# Kinds whose pattern alone would over-match, filtered by a checksum before the
# span is ever emitted.  This runs at *detection* time on purpose: the optional
# ``llm_validation`` backend defaults to off, and even the "model" backend
# auto-keeps regex spans, so a bare 10-digit NPI or 9-digit ABA match must
# validate itself or it becomes a false-positive generator.
DETECT_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "iban": checksums.iban,
    "npi": checksums.npi,
    "dea_number": checksums.dea_number,
    "us_routing_number": checksums.us_routing_number,
}


def load_custom_patterns(path: str) -> None:
    """Load additional regex patterns from a YAML file.

    Expected format:
      patterns:
        custom_kind: "regex_string"
    """
    from pathlib import Path

    import yaml

    p = Path(path)
    if not p.exists():
        return
    raw = yaml.safe_load(p.read_text()) or {}
    for kind, pattern_str in raw.get("patterns", {}).items():
        _custom_patterns[kind] = re.compile(pattern_str)


def _match_span(match: re.Match[str]) -> tuple[int, int, str]:
    """Prefer the first participating capture group, else the whole match.

    Patterns such as ``password`` use alternation with several groups (double-
    quoted value with spaces, single-quoted, or unquoted); exactly one
    alternative participates per match, so the first non-None group is the
    value to redact.
    """
    for i in range(1, match.re.groups + 1):
        if match.group(i) is not None:
            return match.start(i), match.end(i), match.group(i)
    return match.start(), match.end(), match.group()


def detect_regex(text: str) -> list[Span]:
    """Run all regex patterns against text and return detected spans."""
    spans: list[Span] = []
    all_patterns = {**PATTERNS, **_custom_patterns}
    for kind, pattern in all_patterns.items():
        validator = DETECT_VALIDATORS.get(kind)
        for match in pattern.finditer(text):
            start, end, matched_text = _match_span(match)
            if validator is not None:
                try:
                    if not validator(matched_text):
                        continue
                except Exception:
                    pass  # fail-open: a broken checksum must never unredact
            spans.append(
                Span(
                    start=start,
                    end=end,
                    kind=kind,
                    confidence=1.0,
                    text=matched_text,
                    source="regex",
                )
            )
    return spans
