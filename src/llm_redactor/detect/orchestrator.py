"""Runs all detectors, merges/deduplicates spans, and filters false positives."""

from __future__ import annotations

import re

from .ner import detect_ner
from .regex import detect_regex
from .types import Span

# Common false positives from NER — short words, abbreviations, and
# generic terms that Presidio/spaCy frequently misclassify.
_FP_SUPPRESS: set[str] = {
    # Generic words misclassified as ORG
    "pii",
    "api",
    "ssn",
    "dob",
    "ehr",
    "phi",
    "hipaa",
    "gdpr",
    "sql",
    "csv",
    "json",
    "xml",
    "html",
    "http",
    "https",
    "url",
    "llm",
    "nlp",
    "ner",
    "gpt",
    "ai",
    "ml",
    "dl",
    # Time expressions misclassified as DATE_TIME
    "today",
    "yesterday",
    "tomorrow",
    "now",
    "recently",
    # Quarter references misclassified as various
    "q1",
    "q2",
    "q3",
    "q4",
    # Common nouns misclassified as LOCATION
    "café",
    "cafe",
    "office",
    "home",
    "here",
    "there",
}

# Patterns for false positives that need regex matching.
_FP_PATTERNS: list[re.Pattern[str]] = [
    # Drug names commonly misclassified as PERSON
    re.compile(
        r"(?i)^(?:lisinopril|metformin|atorvastatin|omeprazole|amlodipine|"
        r"metoprolol|losartan|albuterol|gabapentin|hydrochlorothiazide|"
        r"levothyroxine|simvastatin|ibuprofen|acetaminophen|amoxicillin|"
        r"azithromycin|ciprofloxacin|prednisone|sertraline|fluoxetine)$"
    ),
    # DOB/SSN labels misclassified as ORG
    re.compile(r"(?i)^(?:dob|ssn|ein|tin|mrn)\s"),
]


def _is_false_positive(span: Span) -> bool:
    """Check if a NER span is a known false positive."""
    if span.source != "ner":
        return False

    text_lower = span.text.strip().lower()

    # Exact match suppression.
    if text_lower in _FP_SUPPRESS:
        return True

    # Single character or very short non-PII.
    if len(text_lower) <= 2 and span.kind not in {"ssn", "ip_address"}:
        return True

    # Pattern match suppression.
    for pattern in _FP_PATTERNS:
        if pattern.match(span.text.strip()):
            return True

    # Low-confidence NER on very short text (likely noise).
    if span.confidence < 0.4 and len(span.text) < 6:
        return True

    return False


def _merge_overlapping(spans: list[Span]) -> list[Span]:
    """Deduplicate overlapping spans, keeping the highest-confidence one."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    merged: list[Span] = [sorted_spans[0]]

    for span in sorted_spans[1:]:
        prev = merged[-1]
        if span.start < prev.end:
            # Overlapping — keep the one with higher confidence
            if span.confidence > prev.confidence:
                merged[-1] = span
        else:
            merged.append(span)

    return merged


def configure_detection(
    *,
    ner_model: str | None = None,
    ner_confidence_floor: float | None = None,
) -> None:
    """Configure detection parameters. Call before first detect_all()."""
    from .ner import configure_ner

    configure_ner(model_name=ner_model, confidence_floor=ner_confidence_floor)


def detect_all(text: str, use_ner: bool = True) -> list[Span]:
    """Run all enabled detectors and return merged spans."""
    spans = detect_regex(text)

    if use_ner:
        ner_spans = detect_ner(text)
        spans.extend(s for s in ner_spans if not _is_false_positive(s))

    return _merge_overlapping(spans)


async def detect_all_validated(
    text: str,
    *,
    use_ner: bool = True,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> list[Span]:
    """Run all detectors, then validate NER spans with a local LLM.

    This is the high-accuracy path: regex + NER + LLM validation.
    Adds one Ollama round-trip but dramatically reduces false positives
    (drug names, abbreviations, generic words) while confirming real PII.
    """
    from .llm_validator import validate_spans

    spans = detect_regex(text)

    if use_ner:
        ner_spans = detect_ner(text)
        spans.extend(s for s in ner_spans if not _is_false_positive(s))

    merged = _merge_overlapping(spans)

    # LLM validation pass — only validates NER spans (regex are auto-kept).
    validated = await validate_spans(
        text,
        merged,
        endpoint=ollama_endpoint,
        model=ollama_model,
    )

    return validated
