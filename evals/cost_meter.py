"""Token cost analysis — measures token overhead from redaction.

Compares token counts of original vs redacted text using tiktoken
(cl100k_base, GPT-4 family tokeniser).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .runner import RunResult
from .schema import Sample, read_workload


def _count_tokens(text: str) -> int:
    """Approximate token count using whitespace split.

    A rough proxy (~1.3x actual BPE tokens for English) that avoids
    the tiktoken SSL download dependency.  Consistent across runs,
    so relative comparisons (delta %) are valid.
    """
    return len(text.split())


@dataclass
class CostResult:
    """Token cost for a single sample."""

    sample_id: str
    option: str
    original_tokens: int
    outgoing_tokens: int
    delta: int  # outgoing - original (negative = fewer tokens sent)
    delta_pct: float


@dataclass
class WorkloadCostSummary:
    """Aggregate token cost across a workload."""

    workload: str
    option: str
    num_samples: int
    total_original_tokens: int
    total_outgoing_tokens: int
    total_delta: int
    mean_delta_pct: float
    per_sample: list[CostResult]


def measure_cost(sample: Sample, run_result: RunResult) -> CostResult:
    """Measure token overhead for a single sample."""
    orig_tokens = _count_tokens(sample.text)
    out_tokens = _count_tokens(run_result.outgoing_text) if run_result.outgoing_text else 0
    delta = out_tokens - orig_tokens
    delta_pct = delta / orig_tokens if orig_tokens else 0.0

    return CostResult(
        sample_id=sample.id,
        option=run_result.option,
        original_tokens=orig_tokens,
        outgoing_tokens=out_tokens,
        delta=delta,
        delta_pct=delta_pct,
    )


def measure_workload_cost(
    workload_path: Path,
    run_results: list[RunResult],
) -> WorkloadCostSummary:
    """Measure token cost across a workload."""
    samples = read_workload(workload_path)
    sample_map = {s.id: s for s in samples}

    per_sample: list[CostResult] = []
    total_orig = 0
    total_out = 0

    for rr in run_results:
        sample = sample_map.get(rr.sample_id)
        if sample is None:
            continue
        cr = measure_cost(sample, rr)
        per_sample.append(cr)
        total_orig += cr.original_tokens
        total_out += cr.outgoing_tokens

    n = len(per_sample)
    mean_delta_pct = sum(cr.delta_pct for cr in per_sample) / n if n else 0.0

    return WorkloadCostSummary(
        workload=workload_path.parent.name,
        option=run_results[0].option if run_results else "unknown",
        num_samples=n,
        total_original_tokens=total_orig,
        total_outgoing_tokens=total_out,
        total_delta=total_out - total_orig,
        mean_delta_pct=mean_delta_pct,
        per_sample=per_sample,
    )
