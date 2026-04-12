"""CLI to run the evaluation harness.

Usage:
  uv run python -m evals.run_eval                       # all workloads, offline, Option B
  uv run python -m evals.run_eval --workload wl1_pii
  uv run python -m evals.run_eval --use-ner              # include presidio NER
  uv run python -m evals.run_eval --option B+C --use-ner # B+C with NER
  uv run python -m evals.run_eval --option B+C -w wl3_implicit --use-ner
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .leak_meter import measure_workload
from .report import (
    EvalRow,
    add_latency_to_row,
    leak_summary_to_row,
    rows_to_markdown,
    write_report,
)
from .runner import run_workload

WORKLOADS_DIR = Path(__file__).parent / "workloads"
WORKLOADS = ["wl1_pii", "wl2_secrets", "wl3_implicit", "wl4_code"]


def _print_summary(summary) -> None:
    print(f"  Exact leak rate:    {summary.exact_leak_rate:.3f}")
    print(f"  Partial leak rate:  {summary.partial_leak_rate:.3f}")
    print(f"  Combined leak rate: {summary.combined_leak_rate:.3f}")
    print(f"  False positive rate: {summary.false_positive_rate:.3f}")
    if summary.leak_rate_by_kind:
        print(f"  Leak by kind:")
        for kind, rate in sorted(summary.leak_rate_by_kind.items(), key=lambda x: -x[1]):
            print(f"    {kind}: {rate:.3f}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run llm-redactor evaluation")
    parser.add_argument(
        "--workload", "-w",
        choices=WORKLOADS,
        nargs="+",
        default=WORKLOADS,
        help="Workloads to evaluate",
    )
    parser.add_argument(
        "--option",
        choices=["A", "B", "B+C", "B+H", "baseline"],
        default="B",
        help="Option to evaluate",
    )
    parser.add_argument("--use-ner", action="store_true", help="Enable presidio NER")
    parser.add_argument(
        "--epsilon", type=float, default=4.0,
        help="DP epsilon for Option H (lower = more noise)",
    )
    parser.add_argument(
        "--ollama-endpoint",
        default="http://127.0.0.1:11434",
        help="Ollama API endpoint (for Options A, C)",
    )
    parser.add_argument(
        "--ollama-model",
        default="llama3.2:3b",
        help="Ollama model (for Options A, C)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory (default: evals/results_<option>)",
    )
    args = parser.parse_args()

    output = args.output or Path(f"evals/results_{args.option.lower().replace('+', '_')}")

    rows: list[EvalRow] = []
    summaries = []

    for wl_name in args.workload:
        wl_path = WORKLOADS_DIR / wl_name / "annotations.jsonl"
        if not wl_path.exists():
            print(f"Workload {wl_name} not found at {wl_path}, skipping")
            continue

        print(f"Running Option {args.option} (offline) on {wl_name}...")
        results = run_workload(
            wl_path,
            option=args.option,
            use_ner=args.use_ner,
            ollama_endpoint=args.ollama_endpoint,
            ollama_model=args.ollama_model,
            epsilon=args.epsilon,
        )
        print(f"  {len(results)} samples processed")

        # Option-specific stats.
        if args.option == "B+C":
            bc_count = sum(1 for r in results if r.option == "B+C")
            rejected = sum(1 for r in results if r.option == "B(C-rejected)")
            print(f"  Rephrase accepted: {bc_count}, rejected: {rejected}")
        elif args.option == "A":
            local = sum(1 for r in results if r.option == "A(local)")
            cloud = sum(1 for r in results if r.option == "A(cloud)")
            print(f"  Routed local: {local}, routed cloud: {cloud} ({local/(local+cloud)*100:.1f}% local)")

        print(f"Measuring leaks on {wl_name}...")
        summary = measure_workload(wl_path, results)
        summaries.append(summary)

        row = leak_summary_to_row(summary)
        latencies = [r.latency_ms for r in results]
        add_latency_to_row(row, latencies)
        rows.append(row)

        _print_summary(summary)

    if rows:
        print("\n" + rows_to_markdown(rows))
        write_report(rows, output, leak_summaries=summaries)
        print(f"\nResults written to {output}/")


if __name__ == "__main__":
    main()
