"""Runs all detectors and merges/deduplicates spans."""

from __future__ import annotations

from .regex import detect_regex
from .ner import detect_ner
from .types import Span


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


def detect_all(text: str, use_ner: bool = True) -> list[Span]:
    """Run all enabled detectors and return merged spans."""
    spans = detect_regex(text)

    if use_ner:
        spans.extend(detect_ner(text))

    return _merge_overlapping(spans)
