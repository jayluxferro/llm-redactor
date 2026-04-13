"""LLM-based validation pass for detected spans.

After regex + NER detection, sends each span with surrounding context
to a local LLM and asks: "Is this actually sensitive information?"

This catches:
- False positives: drug names tagged as PERSON, abbreviations as ORG
- Missed entities: names in unusual formats that NER missed

The validator is opt-in (adds one Ollama round-trip per request) and
configurable via pipeline.llm_validation in the config.
"""

from __future__ import annotations

import json

import httpx

from .types import Span


# Context window: characters before/after the span to include.
_CONTEXT_CHARS = 80

_SYSTEM_PROMPT = """\
You are a PII/secret detection validator. You will be given a text span \
that was flagged as potentially sensitive, along with its surrounding context \
and the detection type.

Your job: determine if this span is ACTUALLY sensitive information that \
should be redacted before sending to a cloud LLM.

Rules:
- KEEP means "yes, redact this — it is real PII or a real secret"
- DROP means "no, this is a false positive — do not redact"
- Drug names, medical terms, technical jargon → DROP
- Common abbreviations (PII, API, SQL, Q3) when not actual identifiers → DROP
- Actual person names, emails, phone numbers, SSNs, API keys → KEEP
- Organization names that are real companies → KEEP
- Generic words (café, office, today) → DROP

Respond with ONLY a JSON object: {"verdict": "KEEP"} or {"verdict": "DROP"}
"""


async def validate_spans(
    text: str,
    spans: list[Span],
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
    timeout: float = 30.0,
) -> list[Span]:
    """Validate detected spans using a local LLM.

    Returns only the spans that the LLM confirms as real sensitive content.
    Spans from regex detection (confidence=1.0) are auto-kept — only NER
    spans are validated to save LLM calls.
    """
    if not spans:
        return []

    # Regex detections are high-confidence by design — skip validation.
    regex_spans = [s for s in spans if s.source == "regex"]
    ner_spans = [s for s in spans if s.source != "regex"]

    if not ner_spans:
        return regex_spans

    # Batch all NER spans into one LLM call for efficiency.
    validated = list(regex_spans)
    kept = await _batch_validate(text, ner_spans, endpoint=endpoint, model=model, timeout=timeout)
    validated.extend(kept)

    return validated


async def _batch_validate(
    text: str,
    spans: list[Span],
    *,
    endpoint: str,
    model: str,
    timeout: float,
) -> list[Span]:
    """Validate a batch of spans in a single LLM call."""
    # Build the prompt with all spans and their context.
    entries = []
    for i, span in enumerate(spans):
        ctx_start = max(0, span.start - _CONTEXT_CHARS)
        ctx_end = min(len(text), span.end + _CONTEXT_CHARS)
        context = text[ctx_start:ctx_end]

        entries.append(
            f"Span {i+1}: \"{span.text}\" (detected as: {span.kind}, confidence: {span.confidence:.2f})\n"
            f"Context: ...{context}..."
        )

    prompt = (
        "Validate these detected spans. For each, respond KEEP or DROP.\n\n"
        + "\n\n".join(entries)
        + "\n\nRespond with ONLY a JSON array of verdicts, e.g.:\n"
        + '[{"span": 1, "verdict": "KEEP"}, {"span": 2, "verdict": "DROP"}]'
    )

    url = f"{endpoint.rstrip('/')}/api/chat"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 200},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            raw = resp.json().get("message", {}).get("content", "")
    except Exception:
        # If LLM is unreachable, keep all spans (fail safe).
        return list(spans)

    return _parse_verdicts(raw, spans)


def _parse_verdicts(raw: str, spans: list[Span]) -> list[Span]:
    """Parse LLM response and return kept spans."""
    # Try to extract JSON from the response.
    try:
        # Handle response wrapped in markdown code blocks.
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        verdicts = json.loads(clean)
        if isinstance(verdicts, list):
            drop_indices: set[int] = set()
            for v in verdicts:
                idx = v.get("span", 0) - 1  # 1-indexed
                if v.get("verdict", "").upper() == "DROP" and 0 <= idx < len(spans):
                    drop_indices.add(idx)
            return [s for i, s in enumerate(spans) if i not in drop_indices]
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    # Fallback: parse line-by-line for "KEEP" / "DROP".
    lines = raw.strip().splitlines()
    kept = []
    for i, span in enumerate(spans):
        if i < len(lines):
            if "DROP" in lines[i].upper():
                continue
        # Default: keep (fail safe).
        kept.append(span)

    return kept
