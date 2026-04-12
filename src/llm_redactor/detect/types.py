"""Shared types for the detection layer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Span:
    """A detected sensitive span in the input text."""

    start: int
    end: int
    kind: str  # e.g. "email", "person", "api_key", "org_name"
    confidence: float  # 0.0–1.0
    text: str  # the matched substring
    source: str  # which detector found it ("regex", "ner", "classifier")
