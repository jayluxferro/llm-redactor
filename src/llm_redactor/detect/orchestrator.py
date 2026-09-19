"""Runs all detectors, merges/deduplicates spans, and filters false positives."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from .ner import detect_ner
from .regex import detect_regex
from .types import Span

if TYPE_CHECKING:
    from ..config import Config

_LOG = logging.getLogger(__name__)

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
    ner_labels_to_ignore: list[str] | None = None,
) -> None:
    """Configure detection parameters. Call before first detect_all()."""
    from .ner import configure_ner

    configure_ner(
        model_name=ner_model,
        confidence_floor=ner_confidence_floor,
        labels_to_ignore=ner_labels_to_ignore,
    )


def apply_detection_config(cfg: Config) -> None:
    """Apply NER settings from a Config.

    Single source of truth for wiring detection out of config — shared by the
    CLI (in-process commands) and the HTTP proxy's per-worker lifespan, so the
    config→detector mapping lives in exactly one place.
    """
    configure_detection(
        ner_model=cfg.local_model.ner_model,
        ner_confidence_floor=cfg.local_model.ner_confidence_floor,
        ner_labels_to_ignore=cfg.local_model.ner_labels_to_ignore,
    )


def _detect_and_merge(text: str, use_ner: bool) -> list[Span]:
    """Synchronous regex + NER detection and overlap merge.

    This is the CPU-heavy, blocking part of detection (spaCy NER in particular).
    It is factored out so async callers can push it onto a worker thread via
    ``asyncio.to_thread`` — running it inline on the event loop would stall
    uvicorn's ``accept()`` under concurrent load and make the proxy look
    unreachable to the gateway.
    """
    spans = detect_regex(text)

    if use_ner:
        try:
            ner_spans = detect_ner(text)
        except Exception as exc:
            # The proxy must remain useful when a local model is unavailable
            # (for example, a first-run spaCy download blocked by a corporate
            # TLS proxy). Regex detections are still safe to apply.
            _LOG.warning("NER unavailable; continuing with regex detection: %s", type(exc).__name__)
            ner_spans = []
        spans.extend(s for s in ner_spans if not _is_false_positive(s))

    return _merge_overlapping(spans)


def detect_all(text: str, use_ner: bool = True) -> list[Span]:
    """Run all enabled detectors and return merged spans (synchronous)."""
    return _detect_and_merge(text, use_ner)


async def detect_all_validated(
    text: str,
    *,
    use_ner: bool = True,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
    backend: str = "model",
) -> list[Span]:
    """Run all detectors, then validate spans.

    Two backends:

    - ``"model"`` (default): ask a local Ollama chat model for KEEP/DROP
      verdicts on NER spans. Adds one round-trip but dramatically reduces
      false positives (drug names, abbreviations, generic words) while
      confirming real PII.
    - ``"rules"``: deterministic checksum/shape rules per kind. No Ollama,
      and regex-sourced spans are validated too (a regex credit_card match
      with a failing Luhn checksum is dropped instead of auto-kept).
    """
    if backend not in {"model", "rules"}:
        # Guard direct callers that bypass config loading (where the same
        # check runs in LLMValidationConfig.__post_init__).
        raise ValueError(f"llm_validation backend must be 'model' or 'rules', got {backend!r}")

    # Push the blocking regex+NER work onto a thread so the event loop stays
    # free to accept new connections while spaCy runs.
    merged = await asyncio.to_thread(_detect_and_merge, text, use_ner)

    # Validation pass — fail-open: if the validator itself breaks, keep the
    # detected spans (detection quality degrades gracefully, never fatally).
    try:
        if backend == "rules":
            from .rules_validator import validate_spans_rules

            return validate_spans_rules(merged)

        from .llm_validator import validate_spans

        return await validate_spans(
            text,
            merged,
            endpoint=ollama_endpoint,
            model=ollama_model,
        )
    except Exception as exc:
        _LOG.warning(
            "%s validation unavailable; retaining detected spans: %s",
            backend,
            type(exc).__name__,
        )
        return merged
