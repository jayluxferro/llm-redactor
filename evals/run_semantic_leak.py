"""Run semantic leak evaluation on WL3 using a local judge model.

Usage:
  uv run python -m evals.run_semantic_leak
  uv run python -m evals.run_semantic_leak --option B+C --max-samples 20
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .leak_meter import measure_semantic_leak
from .runner import run_workload
from .schema import read_workload as read_samples

WL3_PATH = Path(__file__).parent / "workloads" / "wl3_implicit" / "annotations.jsonl"


def run_semantic_eval(
    option: str,
    *,
    use_ner: bool = False,
    max_samples: int | None = None,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
    epsilon: float = 4.0,
) -> dict:
    """Run option on WL3, then judge each sample for semantic leak."""
    results = run_workload(
        WL3_PATH,
        option=option,
        use_ner=use_ner,
        ollama_endpoint=ollama_endpoint,
        ollama_model=ollama_model,
        epsilon=epsilon,
        max_samples=max_samples,
    )
    samples = read_samples(WL3_PATH)
    if max_samples:
        samples = samples[:max_samples]
    sample_map = {s.id: s for s in samples}

    semantic_results = []
    for rr in results:
        sample = sample_map.get(rr.sample_id)
        if sample is None:
            continue
        sr = asyncio.run(
            measure_semantic_leak(
                sample,
                rr,
                ollama_endpoint=ollama_endpoint,
                ollama_model=ollama_model,
            )
        )
        semantic_results.append(sr)
        status = "LEAK" if sr.still_identifies else "safe"
        print(f"  [{status}] {sr.sample_id}: {sr.judge_rationale[:80]}")

    total = len(semantic_results)
    leaks = sum(1 for sr in semantic_results if sr.still_identifies)
    rate = leaks / total if total else 0.0

    return {
        "option": option,
        "workload": "wl3_implicit",
        "total_samples": total,
        "semantic_leaks": leaks,
        "semantic_leak_rate": round(rate, 4),
        "details": [
            {
                "sample_id": sr.sample_id,
                "still_identifies": sr.still_identifies,
                "rationale": sr.judge_rationale,
            }
            for sr in semantic_results
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Semantic leak evaluation on WL3")
    parser.add_argument("--option", default="B", choices=["B", "B+C", "B+H", "B+D", "baseline"])
    parser.add_argument("--use-ner", action="store_true")
    parser.add_argument("--max-samples", type=int, default=20)
    parser.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--ollama-model", default="llama3.2:3b")
    parser.add_argument("--epsilon", type=float, default=4.0)
    parser.add_argument("--output", "-o", type=Path, default=Path("evals/results_semantic"))
    args = parser.parse_args()

    print(f"Running semantic leak eval: option={args.option}, max_samples={args.max_samples}")
    summary = run_semantic_eval(
        args.option,
        use_ner=args.use_ner,
        max_samples=args.max_samples,
        ollama_endpoint=args.ollama_endpoint,
        ollama_model=args.ollama_model,
        epsilon=args.epsilon,
    )

    print(
        f"\nSemantic leak rate: {summary['semantic_leak_rate']:.1%} "
        f"({summary['semantic_leaks']}/{summary['total_samples']})"
    )

    args.output.mkdir(parents=True, exist_ok=True)
    out_path = args.output / f"semantic_{args.option.replace('+', '_').lower()}.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Results written to {out_path}")


if __name__ == "__main__":
    main()
