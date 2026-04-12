"""Validator: checks that rephrased text preserves key technical terms.

Prevents over-rewriting — if the rephrase strips load-bearing technical
context, the cloud model can't answer the question properly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Terms that should survive rephrasing. These are technical/domain terms
# that the cloud model needs to produce a useful answer.
# This is intentionally broad; false negatives (passing a bad rephrase)
# are worse than false positives (rejecting a fine rephrase).
TECHNICAL_TERM_PATTERNS = [
    # Programming languages and frameworks
    r"\b(?:Python|Java|JavaScript|TypeScript|Go|Rust|Ruby|C\+\+|SQL|HTML|CSS)\b",
    r"\b(?:React|FastAPI|Django|Flask|Spring|Rails|Express|Next\.js|Vue)\b",
    # Infrastructure and tools
    r"\b(?:Docker|Kubernetes|AWS|GCP|Azure|Terraform|Ansible|PostgreSQL|Redis|Kafka)\b",
    r"\b(?:API|REST|GraphQL|gRPC|HTTP|HTTPS|TCP|UDP|DNS|SSH|TLS|SSL)\b",
    # Common technical verbs/nouns that are domain-specific
    r"\b(?:deploy|migration|schema|endpoint|query|index|cache|pipeline|webhook)\b",
    r"\b(?:authentication|authorization|token|session|certificate|encryption)\b",
    r"\b(?:debug|error|exception|traceback|stack trace|segfault|timeout|deadlock)\b",
    r"\b(?:database|table|column|row|foreign key|primary key|constraint)\b",
    # Code patterns (function calls, imports, etc.)
    r"(?:def |class |import |from |SELECT |INSERT |UPDATE |DELETE |CREATE |ALTER )",
]


@dataclass
class ValidationResult:
    """Result of validating a rephrase."""

    valid: bool
    original_terms: list[str]
    surviving_terms: list[str]
    dropped_terms: list[str]
    survival_rate: float


def extract_technical_terms(text: str) -> list[str]:
    """Extract technical terms from text using pattern matching."""
    terms: list[str] = []
    seen: set[str] = set()
    for pattern in TECHNICAL_TERM_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            term = match.group().strip()
            key = term.lower()
            if key not in seen:
                seen.add(key)
                terms.append(term)
    return terms


def validate_rephrase(
    original: str,
    rephrased: str,
    *,
    min_survival_rate: float = 0.7,
) -> ValidationResult:
    """Check that the rephrased text preserves key technical terms.

    Returns a ValidationResult. If survival_rate < min_survival_rate,
    valid=False and the caller should roll back the rephrase.
    """
    original_terms = extract_technical_terms(original)

    if not original_terms:
        # No technical terms to preserve — rephrase is valid by default.
        return ValidationResult(
            valid=True,
            original_terms=[],
            surviving_terms=[],
            dropped_terms=[],
            survival_rate=1.0,
        )

    rephrased_lower = rephrased.lower()
    surviving = [t for t in original_terms if t.lower() in rephrased_lower]
    dropped = [t for t in original_terms if t.lower() not in rephrased_lower]
    rate = len(surviving) / len(original_terms)

    return ValidationResult(
        valid=rate >= min_survival_rate,
        original_terms=original_terms,
        surviving_terms=surviving,
        dropped_terms=dropped,
        survival_rate=rate,
    )
