"""Regex-based detector for secrets and structured PII."""

from __future__ import annotations

import re

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

    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
    ),
    "phone_intl": re.compile(
        r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{1,4})?"
    ),
    "ssn": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    ),
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
    "employee_id": re.compile(
        r"\bEMP-\d{4,6}\b"
    ),

    # ── Passwords & secrets in assignments ────────────────────────────────

    "password": re.compile(
        r"(?i)(?:password|passwd|pwd|pass)[\s]*[=:]\s*['\"]?(\S{4,})['\"]?"
    ),
    "secret_assignment": re.compile(
        r"(?i)(?:secret|token|credential|auth)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.+/=]{8,})['\"]?"
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
        r"(?i)(?:aws)?[_\-]?(?:secret)?[_\-]?(?:access)?[_\-]?key[\s]*[=:]\s*['\"]?"
        r"([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "aws_session_token": re.compile(
        r"(?i)aws[_\-]?session[_\-]?token[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"
    ),

    # GCP
    "gcp_service_account": re.compile(
        r"\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b"
    ),
    "gcp_api_key": re.compile(
        r"\bAIza[0-9A-Za-z\-_]{35}\b"
    ),

    # Azure
    "azure_storage_key": re.compile(
        r"(?i)(?:account[_\-]?key|storage[_\-]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?"
    ),
    "azure_connection_string": re.compile(
        r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"
    ),

    # ── API keys by vendor ────────────────────────────────────────────────

    "openai_api_key": re.compile(
        r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b"
    ),
    "anthropic_api_key": re.compile(
        r"\bsk-ant-(?:api03-)?[a-zA-Z0-9\-_]{20,}\b"
    ),
    "github_token": re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"
    ),
    "gitlab_token": re.compile(
        r"\bgl(?:pat|ptt|dt|rt|at)-[A-Za-z0-9\-_]{20,}\b"
    ),
    "slack_token": re.compile(
        r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"
    ),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
    ),
    "stripe_key": re.compile(
        r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b"
    ),
    "twilio_key": re.compile(
        r"\bSK[0-9a-fA-F]{32}\b"
    ),
    "sendgrid_key": re.compile(
        r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{20,}\b"
    ),
    "mailgun_key": re.compile(
        r"\bkey-[0-9a-zA-Z]{32}\b"
    ),
    "npm_token": re.compile(
        r"\bnpm_[A-Za-z0-9]{36}\b"
    ),
    "pypi_token": re.compile(
        r"\bpypi-[A-Za-z0-9\-_]{50,}\b"
    ),
    "heroku_api_key": re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),

    # ── Generic patterns ──────────────────────────────────────────────────

    "generic_api_key": re.compile(
        r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"
        r"[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.+/=]{16,})['\"]?"
    ),
    "bearer_token": re.compile(
        r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*"
    ),
    "basic_auth": re.compile(
        r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b"
    ),
    "private_key_pem": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "ssh_private_key": re.compile(
        r"-----BEGIN OPENSSH PRIVATE KEY-----"
    ),
    "pgp_private_key": re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
    ),

    # ── Hostnames ─────────────────────────────────────────────────────────

    "hostname_internal": re.compile(
        r"\b[a-z][a-z0-9\-]+\.(?:internal|local|corp|lan|intranet|private|staging|dev)\b"
    ),
}


_custom_patterns: dict[str, re.Pattern[str]] = {}


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


def detect_regex(text: str) -> list[Span]:
    """Run all regex patterns against text and return detected spans."""
    spans: list[Span] = []
    all_patterns = {**PATTERNS, **_custom_patterns}
    for kind, pattern in all_patterns.items():
        for match in pattern.finditer(text):
            # Use the full match or group(1) if the pattern captures a group
            if match.lastindex and match.lastindex >= 1:
                start, end = match.start(1), match.end(1)
                matched_text = match.group(1)
            else:
                start, end = match.start(), match.end()
                matched_text = match.group()
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
