"""Report aggregator — produces summary tables and figures from eval results.

Outputs:
  - Markdown summary table (leak rates per option × workload)
  - CSV for paper import
  - Optionally matplotlib figures (if matplotlib available)
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .leak_meter import WorkloadLeakSummary
from .utility_meter import WorkloadUtilitySummary


@dataclass
class EvalRow:
    """One row in the results matrix (option × workload)."""

    option: str
    workload: str
    num_samples: int
    total_annotations: int
    exact_leak_rate: float
    partial_leak_rate: float
    combined_leak_rate: float
    false_positive_rate: float
    # Utility fields (filled only if utility data available).
    quality_delta: float | None = None  # mean judge score
    baseline_preferred_pct: float | None = None
    # Latency.
    latency_ms_median: float | None = None
    latency_ms_p95: float | None = None


def leak_summary_to_row(summary: WorkloadLeakSummary) -> EvalRow:
    """Convert a WorkloadLeakSummary to an EvalRow."""
    latencies = [lr.latency_ms_median for lr in []]  # placeholder
    return EvalRow(
        option=summary.option,
        workload=summary.workload,
        num_samples=summary.num_samples,
        total_annotations=summary.total_annotations,
        exact_leak_rate=summary.exact_leak_rate,
        partial_leak_rate=summary.partial_leak_rate,
        combined_leak_rate=summary.combined_leak_rate,
        false_positive_rate=summary.false_positive_rate,
    )


def add_latency_to_row(
    row: EvalRow,
    latencies_ms: list[float],
) -> EvalRow:
    """Add latency stats to an EvalRow."""
    if not latencies_ms:
        return row
    sorted_lat = sorted(latencies_ms)
    n = len(sorted_lat)
    row.latency_ms_median = sorted_lat[n // 2]
    row.latency_ms_p95 = sorted_lat[int(n * 0.95)]
    return row


def add_utility_to_row(
    row: EvalRow,
    utility: WorkloadUtilitySummary,
) -> EvalRow:
    """Add utility stats to an EvalRow."""
    row.quality_delta = utility.mean_score
    total = utility.num_samples
    row.baseline_preferred_pct = utility.baseline_preferred / total if total else None
    return row


# --- Output formatters ---


def rows_to_markdown(rows: list[EvalRow]) -> str:
    """Format rows as a Markdown table."""
    lines = [
        "| Option | Workload | Samples | Exact Leak | Partial Leak | Combined | FP Rate | Quality Δ | Latency p50 | Latency p95 |",
        "|--------|----------|--------:|-----------:|-------------:|---------:|--------:|----------:|------------:|------------:|",
    ]
    for r in rows:
        qd = f"{r.quality_delta:+.3f}" if r.quality_delta is not None else "—"
        lp50 = f"{r.latency_ms_median:.1f}" if r.latency_ms_median is not None else "—"
        lp95 = f"{r.latency_ms_p95:.1f}" if r.latency_ms_p95 is not None else "—"
        lines.append(
            f"| {r.option} | {r.workload} | {r.num_samples} | "
            f"{r.exact_leak_rate:.3f} | {r.partial_leak_rate:.3f} | "
            f"{r.combined_leak_rate:.3f} | {r.false_positive_rate:.3f} | "
            f"{qd} | {lp50} | {lp95} |"
        )
    return "\n".join(lines)


def rows_to_csv(rows: list[EvalRow]) -> str:
    """Format rows as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "option", "workload", "num_samples", "total_annotations",
        "exact_leak_rate", "partial_leak_rate", "combined_leak_rate",
        "false_positive_rate", "quality_delta",
        "latency_ms_median", "latency_ms_p95",
    ])
    for r in rows:
        writer.writerow([
            r.option, r.workload, r.num_samples, r.total_annotations,
            f"{r.exact_leak_rate:.6f}", f"{r.partial_leak_rate:.6f}",
            f"{r.combined_leak_rate:.6f}", f"{r.false_positive_rate:.6f}",
            f"{r.quality_delta:.6f}" if r.quality_delta is not None else "",
            f"{r.latency_ms_median:.3f}" if r.latency_ms_median is not None else "",
            f"{r.latency_ms_p95:.3f}" if r.latency_ms_p95 is not None else "",
        ])
    return buf.getvalue()


def rows_to_latex(rows: list[EvalRow]) -> str:
    """Format rows as a LaTeX table body (for paper.tex)."""
    lines = []
    for r in rows:
        qd = f"{r.quality_delta:+.3f}" if r.quality_delta is not None else "---"
        lp50 = f"{r.latency_ms_median:.1f}" if r.latency_ms_median is not None else "---"
        lines.append(
            f"  {r.option} & {r.workload} & {r.num_samples} & "
            f"{r.exact_leak_rate:.3f} & {r.partial_leak_rate:.3f} & "
            f"{r.combined_leak_rate:.3f} & {r.false_positive_rate:.3f} & "
            f"{qd} & {lp50} \\\\"
        )
    return "\n".join(lines)


def leak_breakdown_by_kind(summary: WorkloadLeakSummary) -> str:
    """Markdown table of leak rates per annotation kind."""
    lines = [
        "| Kind | Leak Rate |",
        "|------|----------:|",
    ]
    for kind, rate in sorted(summary.leak_rate_by_kind.items(), key=lambda x: -x[1]):
        lines.append(f"| {kind} | {rate:.3f} |")
    return "\n".join(lines)


def write_report(
    rows: list[EvalRow],
    output_dir: Path,
    *,
    leak_summaries: list[WorkloadLeakSummary] | None = None,
) -> None:
    """Write all report artifacts to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "results.md").write_text(rows_to_markdown(rows))
    (output_dir / "results.csv").write_text(rows_to_csv(rows))
    (output_dir / "results_latex.tex").write_text(rows_to_latex(rows))

    if leak_summaries:
        parts = []
        for s in leak_summaries:
            parts.append(f"\n### {s.workload} ({s.option})\n")
            parts.append(leak_breakdown_by_kind(s))
        (output_dir / "leak_breakdown.md").write_text("\n".join(parts))

    # Try to generate figures if matplotlib is available.
    try:
        _generate_figures(rows, output_dir)
    except ImportError:
        pass


def _generate_figures(rows: list[EvalRow], output_dir: Path) -> None:
    """Generate matplotlib figures for the paper."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Grouped bar chart: exact leak rate per workload.
    workloads = sorted(set(r.workload for r in rows))
    options = sorted(set(r.option for r in rows))

    fig, ax = plt.subplots(figsize=(10, 5))
    width = 0.8 / max(len(options), 1)
    for i, opt in enumerate(options):
        rates = []
        for wl in workloads:
            matching = [r for r in rows if r.option == opt and r.workload == wl]
            rates.append(matching[0].exact_leak_rate if matching else 0.0)
        positions = [x + i * width for x in range(len(workloads))]
        ax.bar(positions, rates, width, label=opt)

    ax.set_xlabel("Workload")
    ax.set_ylabel("Exact Leak Rate")
    ax.set_title("Residual Leak Rate per Option per Workload")
    ax.set_xticks([x + width * (len(options) - 1) / 2 for x in range(len(workloads))])
    ax.set_xticklabels(workloads)
    ax.legend()
    ax.set_ylim(0, 1.0)
    fig.tight_layout()
    fig.savefig(output_dir / "leak_rates.pdf")
    fig.savefig(output_dir / "leak_rates.png", dpi=150)
    plt.close(fig)
