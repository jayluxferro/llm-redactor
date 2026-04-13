"""Regex-based detector for secrets and structured PII."""

from __future__ import annotations

import re

from .types import Span

# Pattern families — extend via config's extend_patterns_file.
PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "ip_v4": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "aws_access_key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
    "aws_secret_key": re.compile(
        r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?"
    ),
    "bearer_token": re.compile(
        r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*"
    ),
    "pem_private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
    ),
    "ssh_private_key": re.compile(
        r"-----BEGIN OPENSSH PRIVATE KEY-----"
    ),
    "employee_id": re.compile(
        r"\bEMP-\d{4,6}\b"
    ),
    "password": re.compile(
        r"(?i)(?:password|passwd|pwd)[\s]*[=:]\s*['\"]?(\S{4,})['\"]?"
    ),
    "hostname_internal": re.compile(
        r"\b[a-z][a-z0-9\-]+\.(?:internal|local|corp|lan|intranet)\b"
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
