"""Leak meter — measures how much sensitive content survived the pipeline.

Three levels of leak measurement:

1. **Exact leak**: ground-truth annotation text appears verbatim in outgoing text.
2. **Partial leak**: a substring (≥4 chars) of the annotation appears in outgoing text.
3. **Semantic leak** (WL3 only): a judge model determines whether the redacted text
   still identifies the same individual/org. Requires an API call.

All rates are fractions in [0.0, 1.0].
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .runner import RunResult
from .schema import Annotation, Sample, read_workload


MIN_PARTIAL_LEN = 4  # minimum substring length for partial leak


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


def measure_leaks(
    sample: Sample,
    run_result: RunResult,
) -> LeakResult:
    """Measure leak rates by comparing annotations against outgoing text."""
    outgoing = run_result.outgoing_text
    exact_leaks = 0
    partial_leaks = 0
    leaked_kinds: dict[str, int] = {}
    details: list[dict] = []

    for ann in sample.annotations:
        exact = ann.text in outgoing
        partial = False

        if not exact:
            # Check substrings of the annotation text.
            partial = _has_partial_leak(ann.text, outgoing)

        if exact:
            exact_leaks += 1
            leaked_kinds[ann.kind] = leaked_kinds.get(ann.kind, 0) + 1

        if partial and not exact:
            partial_leaks += 1

        details.append({
            "kind": ann.kind,
            "text": ann.text,
            "exact_leak": exact,
            "partial_leak": partial,
        })

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


def _has_partial_leak(annotation_text: str, outgoing: str) -> bool:
    """Check if any substring of annotation_text (≥ MIN_PARTIAL_LEN chars)
    appears in the outgoing text.

    For multi-word annotations (e.g. "Alice Hernandez"), check each word
    individually as well as sliding windows.
    """
    # Check individual words first (most common partial leak).
    words = annotation_text.split()
    for word in words:
        if len(word) >= MIN_PARTIAL_LEN and word in outgoing:
            return True

    # Sliding window over the full string.
    for length in range(MIN_PARTIAL_LEN, len(annotation_text)):
        for start in range(len(annotation_text) - length + 1):
            substr = annotation_text[start : start + length]
            if substr in outgoing:
                return True

    return False


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
    false_positive_rate: float  # detected spans that were NOT in annotations
    per_sample: list[LeakResult]


def measure_workload(
    workload_path: Path,
    run_results: list[RunResult],
) -> WorkloadLeakSummary:
    """Measure leaks across an entire workload."""
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

        # False positive counting.
        ann_texts = {a.text for a in sample.annotations}
        for det in rr.detections:
            total_detections += 1
            if det["text"] in ann_texts:
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
    fp_rate = fp / total_detections if total_detections else 0.0

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
        false_positive_rate=fp_rate,
        per_sample=per_sample,
    )
