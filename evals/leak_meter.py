"""Leak meter — measures how much sensitive content survived the pipeline.

Three levels of leak measurement:

1. **Exact leak**: ground-truth annotation text appears verbatim in outgoing text.
2. **Partial leak**: an *informative token* of the annotation (a word of at
   least 4 characters that is not a stopword) appears as a whole word in the
   outgoing text, and the sample's non-sensitive text does not contain it
   (otherwise its presence proves nothing).  Perfect redaction scores 0 by
   construction (pinned by a test).  The old definition, "any 4-character
   substring", scored perfect redaction as leaking up to 71% on WL3
   ("rene" in "renewal" leaked "Irene"; "the " leaked every phrase).

Both are evaluated against the outgoing text with placeholder tokens stripped
(see ``_redacted_view``).  Placeholders embed the kind name — ``⟨PRIVATE_KEY_PEM_1⟩`` —
so matching them directly counts the placeholder's own words as surviving
sensitive text and inflates the rate for exactly the kinds we most care about.
3. **Semantic leak** (WL3 only): a judge model determines whether the redacted text
   still identifies the same individual/org. Requires an API call.

All rates are fractions in [0.0, 1.0].
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .runner import RunResult
from .schema import Sample, read_workload

MIN_PARTIAL_LEN = 4  # minimum length of an informative token

_TOKEN = re.compile(r"\w+")
# Function words: a shared "with" or "from" is not evidence of anything.
_STOPWORDS = frozenset(
    "about after also been before being between both could does from have here into "
    "just more most much only other over same should some such than that their them "
    "then there these they this those through under very were what when where which "
    "while will with would your".split()
)

# Placeholder tokens, e.g. ``⟨PRIVATE_KEY_PEM_1⟩``.
_PLACEHOLDER = re.compile(r"⟨[^⟩]*⟩")


def _redacted_view(outgoing: str) -> str:
    """Outgoing text with placeholder tokens elided, for leak matching.

    A redacted PEM header used to score as a 1.00 leak purely because the
    placeholder that replaced it, ``⟨PRIVATE_KEY_PEM_1⟩``, contains the word
    PRIVATE that the annotation also contains.  Placeholder bytes are not the
    source text, so they must not count as surviving content.
    """
    return _PLACEHOLDER.sub(" ", outgoing)


@dataclass
class LeakResult:
    """Leak measurement for a single sample."""

    sample_id: str
    option: str
    total_annotations: int
    exact_leaks: int
    partial_leaks: int  # excludes exact leaks (partial-only)
    exact_leak_rate: float
    partial_leak_rate: float
    combined_leak_rate: float  # exact + partial
    leaked_kinds: dict[str, int]  # kind → count of exact leaks
    details: list[dict]  # per-annotation detail


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN.findall(text)}


def _informative(text: str) -> set[str]:
    return {t for t in _tokens(text) if len(t) >= MIN_PARTIAL_LEN and t not in _STOPWORDS}


def _outside_tokens(sample: Sample) -> set[str]:
    """Tokens of the sample's NON-sensitive text (every annotation masked)."""
    chars = list(sample.text)
    for ann in sample.annotations:
        for i in range(max(ann.start, 0), min(ann.end, len(chars))):
            chars[i] = " "
    return _tokens("".join(chars))


def measure_leaks(
    sample: Sample,
    run_result: RunResult,
) -> LeakResult:
    """Measure leak rates by comparing annotations against outgoing text."""
    outgoing = _redacted_view(run_result.outgoing_text)
    sent_tokens = _tokens(outgoing)
    outside = _outside_tokens(sample)
    exact_leaks = 0
    partial_leaks = 0
    leaked_kinds: dict[str, int] = {}
    details: list[dict] = []

    for ann in sample.annotations:
        exact = ann.text in outgoing
        partial = False

        if not exact:
            partial = bool((_informative(ann.text) - outside) & sent_tokens)

        if exact:
            exact_leaks += 1
            leaked_kinds[ann.kind] = leaked_kinds.get(ann.kind, 0) + 1

        if partial and not exact:
            partial_leaks += 1

        details.append(
            {
                "kind": ann.kind,
                "text": ann.text,
                "exact_leak": exact,
                "partial_leak": partial,
            }
        )

    total = len(sample.annotations)
    exact_rate = exact_leaks / total if total else 0.0
    partial_rate = partial_leaks / total if total else 0.0
    combined_rate = (exact_leaks + partial_leaks) / total if total else 0.0

    return LeakResult(
        sample_id=sample.id,
        option=run_result.option,
        total_annotations=total,
        exact_leaks=exact_leaks,
        partial_leaks=partial_leaks,
        exact_leak_rate=exact_rate,
        partial_leak_rate=partial_rate,
        combined_leak_rate=combined_rate,
        leaked_kinds=leaked_kinds,
        details=details,
    )


@dataclass
class SemanticLeakResult:
    """Semantic leak measurement for a single sample (WL3 implicit identity)."""

    sample_id: str
    option: str
    still_identifies: bool
    judge_rationale: str
    # The judge call failed or gave no YES/NO verdict.  Such samples must be
    # excluded from the rate: counting them as "safe" reported a 0% semantic
    # leak rate whenever Ollama was down.
    judge_error: bool = False


_VERDICT = re.compile(r"^\W*(YES|NO)\b", re.IGNORECASE)  # tolerates **YES**, "Yes," ...


async def measure_semantic_leak(
    sample: Sample,
    run_result: RunResult,
    *,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> SemanticLeakResult:
    """Use a local judge model to determine if redacted text still
    identifies the individual/organisation described in the annotation.

    This is the appropriate metric for WL3 (implicit identity), where
    substring matching produces noisy results.
    """
    import httpx

    annotations_desc = "; ".join(f"{a.kind}: {a.text}" for a in sample.annotations)

    prompt = (
        f"Original text describes these sensitive entities: {annotations_desc}\n\n"
        f"Redacted/transformed text:\n{run_result.outgoing_text}\n\n"
        f"Can the redacted text still be used to identify the same person or "
        f"organisation? Answer YES or NO, then explain in one sentence."
    )

    url = f"{ollama_endpoint.rstrip('/')}/api/chat"
    body = {
        "model": ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 60},
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            raw = resp.json().get("message", {}).get("content", "")
    except Exception as exc:
        return SemanticLeakResult(
            sample_id=sample.id,
            option=run_result.option,
            still_identifies=False,
            judge_rationale=f"judge call failed: {type(exc).__name__}",
            judge_error=True,
        )

    verdict = _VERDICT.match(raw.strip())
    return SemanticLeakResult(
        sample_id=sample.id,
        option=run_result.option,
        still_identifies=verdict is not None and verdict.group(1).upper() == "YES",
        judge_rationale=raw.strip()[:200],
        judge_error=verdict is None,
    )


@dataclass
class WorkloadLeakSummary:
    """Aggregate leak metrics across a workload."""

    workload: str
    option: str
    num_samples: int
    total_annotations: int
    total_exact_leaks: int
    total_partial_leaks: int
    exact_leak_rate: float
    partial_leak_rate: float
    combined_leak_rate: float
    leak_rate_by_kind: dict[str, float]  # kind → exact leak rate
    # Detected spans overlapping no annotation, over all detected spans with
    # offsets: a false DISCOVERY rate (the denominator is detections, not
    # negatives).  Detections without offsets (non-span options) are skipped.
    false_discovery_rate: float
    per_sample: list[LeakResult]


def measure_workload(
    workload_path: Path,
    run_results: list[RunResult],
    *,
    option: str | None = None,
) -> WorkloadLeakSummary:
    """Measure leaks across an entire workload.

    ``option`` labels the summary; pass the option that was requested.  The
    fallback, the first sample's route (``A(local)``, ``B(C-rejected)``),
    varies with which sample happens to come first.
    """
    samples = read_workload(workload_path)
    sample_map = {s.id: s for s in samples}

    per_sample: list[LeakResult] = []
    total_annotations = 0
    total_exact = 0
    total_partial = 0
    kind_total: dict[str, int] = {}
    kind_leaked: dict[str, int] = {}

    # Count false positives: detections that don't match any annotation.
    total_detections = 0
    true_positive_detections = 0

    for rr in run_results:
        sample = sample_map.get(rr.sample_id)
        if sample is None:
            continue

        lr = measure_leaks(sample, rr)
        per_sample.append(lr)

        total_annotations += lr.total_annotations
        total_exact += lr.exact_leaks
        total_partial += lr.partial_leaks

        for ann in sample.annotations:
            kind_total[ann.kind] = kind_total.get(ann.kind, 0) + 1

        for kind, count in lr.leaked_kinds.items():
            kind_leaked[kind] = kind_leaked.get(kind, 0) + count

        # False discoveries: span detections that overlap no annotation.  (Exact
        # text equality used to count "Bearer <token>" against an annotated
        # "<token>" as a false positive: 154 of 154 on wl2 overlapped truth.)
        for det in rr.detections:
            if "start" not in det or "end" not in det:
                continue
            total_detections += 1
            if any(det["start"] < a.end and a.start < det["end"] for a in sample.annotations):
                true_positive_detections += 1

    exact_rate = total_exact / total_annotations if total_annotations else 0.0
    partial_rate = total_partial / total_annotations if total_annotations else 0.0
    combined_rate = (total_exact + total_partial) / total_annotations if total_annotations else 0.0

    leak_by_kind: dict[str, float] = {}
    for kind in kind_total:
        kt = kind_total[kind]
        kl = kind_leaked.get(kind, 0)
        leak_by_kind[kind] = kl / kt if kt else 0.0

    fp = total_detections - true_positive_detections
    fdr = fp / total_detections if total_detections else 0.0

    if option is None:
        option = run_results[0].option if run_results else "unknown"

    return WorkloadLeakSummary(
        workload=workload_path.parent.name,
        option=option,
        num_samples=len(per_sample),
        total_annotations=total_annotations,
        total_exact_leaks=total_exact,
        total_partial_leaks=total_partial,
        exact_leak_rate=exact_rate,
        partial_leak_rate=partial_rate,
        combined_leak_rate=combined_rate,
        leak_rate_by_kind=leak_by_kind,
        false_discovery_rate=fdr,
        per_sample=per_sample,
    )
