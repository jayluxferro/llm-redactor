"""Typed placeholder generator with in-memory reverse map."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..detect.types import Span

# Use rare Unicode angle brackets to avoid collisions with user text.
# Users asking about placeholder syntax won't accidentally trigger restoration.
PREFIX = "\u27e8"  # ⟨
SUFFIX = "\u27e9"  # ⟩


@dataclass
class RedactionResult:
    """The output of a redaction pass."""

    redacted_text: str
    reverse_map: dict[str, str]  # placeholder -> original
    placeholders: list[str]  # ordered list of placeholders inserted


@dataclass
class PlaceholderGenerator:
    """Generates stable, typed placeholders for detected spans.

    Two occurrences of the same original text get the same placeholder
    (coreference stability).
    """

    _counters: dict[str, int] = field(default_factory=dict)
    _seen: dict[str, str] = field(default_factory=dict)  # original text -> placeholder

    def _next_placeholder(self, kind: str) -> str:
        count = self._counters.get(kind, 0) + 1
        self._counters[kind] = count
        return f"{PREFIX}{kind.upper()}_{count}{SUFFIX}"

    def get_placeholder(self, span: Span) -> str:
        """Return a stable placeholder for the given span's text."""
        if span.text in self._seen:
            return self._seen[span.text]
        placeholder = self._next_placeholder(span.kind)
        self._seen[span.text] = placeholder
        return placeholder


def redact(text: str, spans: list[Span]) -> RedactionResult:
    """Replace detected spans with placeholders, returning the redacted
    text and the reverse map needed for restoration."""
    if not spans:
        return RedactionResult(redacted_text=text, reverse_map={}, placeholders=[])

    gen = PlaceholderGenerator()

    # Sort spans by start position descending so replacements don't shift offsets.
    sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)

    result = text
    reverse_map: dict[str, str] = {}
    placeholders: list[str] = []

    for span in sorted_spans:
        placeholder = gen.get_placeholder(span)
        reverse_map[placeholder] = span.text
        placeholders.append(placeholder)
        result = result[: span.start] + placeholder + result[span.end :]

    placeholders.reverse()  # restore insertion order
    return RedactionResult(
        redacted_text=result,
        reverse_map=reverse_map,
        placeholders=placeholders,
    )
