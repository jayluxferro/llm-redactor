"""Run online utility evaluation: send baseline + redacted requests, then judge.

Usage:
  uv run python -m evals.run_utility_eval --max-samples 10
  uv run python -m evals.run_utility_eval --workload wl1_pii --option B --max-samples 20
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from .runner import RunResult, run_workload
from .schema import read_workload as read_samples
from .utility_meter import UtilityConfig, measure_workload_utility

WORKLOADS_DIR = Path(__file__).parent / "workloads"
WORKLOADS = ["wl1_pii", "wl2_secrets"]  # focus on PII and secrets


async def get_cloud_response(
    text: str,
    *,
    endpoint: str,
    model: str,
) -> str:
    """Get a response from a cloud/local LLM endpoint."""
    url = f"{endpoint.rstrip('/')}/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "temperature": 0.0,
        "max_tokens": 256,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def run_online_pair(
    sample_text: str,
    redacted_text: str,
    *,
    endpoint: str,
    model: str,
) -> tuple[str, str]:
    """Get responses for both baseline and redacted text."""
    baseline_resp = await get_cloud_response(sample_text, endpoint=endpoint, model=model)
    redacted_resp = await get_cloud_response(redacted_text, endpoint=endpoint, model=model)
    return baseline_resp, redacted_resp


def run_utility_eval(
    workload_name: str,
    option: str,
    *,
    use_ner: bool = True,
    max_samples: int = 10,
    cloud_endpoint: str = "http://localhost:11435/v1",
    cloud_model: str = "mlx-community/Qwen3.5-4B-4bit",
    judge_endpoint: str = "http://localhost:11435/v1",
    judge_model: str = "mlx-community/Qwen3.5-4B-4bit",
    epsilon: float = 4.0,
) -> dict:
    """Run online utility evaluation on a workload."""
    from llm_redactor.redact.restore import restore

    wl_path = WORKLOADS_DIR / workload_name / "annotations.jsonl"

    # Step 1: Run the option offline to get redacted text.
    results = run_workload(
        wl_path,
        option=option,
        use_ner=use_ner,
        max_samples=max_samples,
        epsilon=epsilon,
    )

    samples = read_samples(wl_path)[:max_samples]
    sample_map = {s.id: s for s in samples}

    # Step 2: Get cloud responses for both baseline and redacted.
    baseline_results: list[RunResult] = []
    redacted_results: list[RunResult] = []

    for rr in results:
        sample = sample_map.get(rr.sample_id)
        if sample is None:
            continue

        print(f"  Getting responses for {rr.sample_id}...")
        try:
            baseline_resp, redacted_resp = asyncio.run(
                run_online_pair(
                    sample.text,
                    rr.outgoing_text,
                    endpoint=cloud_endpoint,
                    model=cloud_model,
                )
            )
        except Exception as e:
            print(f"    Error: {e}")
            continue

        restored = restore(redacted_resp, rr.reverse_map) if rr.reverse_map else redacted_resp

        baseline_results.append(
            RunResult(
                sample_id=rr.sample_id,
                option="baseline",
                original_text=sample.text,
                outgoing_text=sample.text,
                response_text=baseline_resp,
                restored_text=baseline_resp,
                detections=[],
                reverse_map={},
                latency_ms=0,
                mode="online",
            )
        )
        redacted_results.append(
            RunResult(
                sample_id=rr.sample_id,
                option=rr.option,
                original_text=sample.text,
                outgoing_text=rr.outgoing_text,
                response_text=redacted_resp,
                restored_text=restored,
                detections=rr.detections,
                reverse_map=rr.reverse_map,
                latency_ms=rr.latency_ms,
                mode="online",
            )
        )

    if not baseline_results:
        return {"error": "No results collected"}

    # Step 3: Judge.
    judge_config = UtilityConfig(
        endpoint=judge_endpoint,
        model=judge_model,
        api_key="not-needed",
        api_format="openai",
    )

    summary = asyncio.run(
        measure_workload_utility(
            workload_name,
            baseline_results,
            redacted_results,
            judge_config,
        )
    )

    return {
        "workload": workload_name,
        "option": option,
        "num_samples": summary.num_samples,
        "baseline_preferred": summary.baseline_preferred,
        "redacted_preferred": summary.redacted_preferred,
        "ties": summary.ties,
        "mean_score": round(summary.mean_score, 4),
        "self_consistency_rate": summary.self_consistency_rate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Online utility evaluation")
    parser.add_argument(
        "--workload",
        "-w",
        default="wl1_pii",
        choices=["wl1_pii", "wl2_secrets", "wl3_implicit", "wl4_code"],
    )
    parser.add_argument("--option", default="B", choices=["B", "B+C", "B+H", "B+D", "A+B", "A+B+C"])
    parser.add_argument("--use-ner", action="store_true", default=True)
    parser.add_argument("--max-samples", type=int, default=10)
    parser.add_argument("--cloud-endpoint", default="http://localhost:11435/v1")
    parser.add_argument("--cloud-model", default="mlx-community/Qwen3.5-4B-4bit")
    parser.add_argument("--judge-endpoint", default="http://localhost:11435/v1")
    parser.add_argument("--judge-model", default="mlx-community/Qwen3.5-4B-4bit")
    parser.add_argument("--output", "-o", type=Path, default=Path("evals/results_utility"))
    args = parser.parse_args()

    print(f"Running utility eval: {args.option} on {args.workload} ({args.max_samples} samples)")
    summary = run_utility_eval(
        args.workload,
        args.option,
        use_ner=args.use_ner,
        max_samples=args.max_samples,
        cloud_endpoint=args.cloud_endpoint,
        cloud_model=args.cloud_model,
        judge_endpoint=args.judge_endpoint,
        judge_model=args.judge_model,
    )

    print(f"\nResults: {json.dumps(summary, indent=2)}")

    args.output.mkdir(parents=True, exist_ok=True)
    out = args.output / f"utility_{args.option.replace('+', '_').lower()}_{args.workload}.json"
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
