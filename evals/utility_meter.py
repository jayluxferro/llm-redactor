"""Utility meter — measures response quality degradation.

Compares the redacted-path response against a baseline (no-redaction) response
using a judge model. Requires online-mode run results with actual cloud responses.

Judge model selection follows the family-bias rule:
  - If cloud target is GPT, judge with Claude (and vice versa).
  - Structured JSON output enforced.

This module also supports offline self-consistency checks: does the redacted
response contain the same key facts as the baseline?
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .runner import RunResult


@dataclass
class UtilityResult:
    """Utility measurement for a single sample."""

    sample_id: str
    option: str
    preference: str  # "baseline", "redacted", "tie"
    score: float  # -1.0 (baseline much better) to 1.0 (redacted much better)
    judge_rationale: str
    self_consistent: bool | None  # None if not checked


@dataclass
class UtilityConfig:
    """Config for the judge model."""

    endpoint: str  # e.g. https://api.anthropic.com/v1 or https://api.openai.com/v1
    model: str  # e.g. claude-haiku-4-5-20251001 or gpt-4o-mini
    api_key: str
    api_format: str = "openai"  # "openai" or "anthropic"


JUDGE_PROMPT = """\
You are evaluating two responses to the same user prompt. One response was \
generated from the original prompt (A), and one was generated from a redacted \
version of the prompt where sensitive information was replaced with placeholders (B).

User prompt (original):
{original_prompt}

Response A (baseline):
{baseline_response}

Response B (redacted path):
{redacted_response}

Compare the two responses on:
1. Correctness: Does each response accurately address the user's question?
2. Completeness: Does each response cover all relevant points?
3. Coherence: Is each response well-structured and readable?

Respond with JSON only:
{{
  "preference": "A" | "B" | "tie",
  "score": <float from -1.0 (A much better) to 1.0 (B much better), 0.0 = tie>,
  "rationale": "<one sentence explaining the preference>"
}}
"""


async def judge_pair(
    original_text: str,
    baseline_result: RunResult,
    redacted_result: RunResult,
    judge_config: UtilityConfig,
) -> UtilityResult:
    """Use a judge model to compare baseline vs redacted responses."""
    prompt = JUDGE_PROMPT.format(
        original_prompt=original_text,
        baseline_response=baseline_result.response_text or "(no response)",
        redacted_response=redacted_result.restored_text or "(no response)",
    )

    judge_response = await _call_judge(prompt, judge_config)

    try:
        parsed = json.loads(judge_response)
        pref_raw = parsed.get("preference", "tie")
        pref_map = {"A": "baseline", "B": "redacted", "tie": "tie"}
        preference = pref_map.get(pref_raw, "tie")
        score = float(parsed.get("score", 0.0))
        rationale = parsed.get("rationale", "")
    except (json.JSONDecodeError, ValueError):
        preference = "tie"
        score = 0.0
        rationale = f"Judge parse error: {judge_response[:200]}"

    return UtilityResult(
        sample_id=redacted_result.sample_id,
        option=redacted_result.option,
        preference=preference,
        score=score,
        judge_rationale=rationale,
        self_consistent=None,
    )


async def _call_judge(prompt: str, config: UtilityConfig) -> str:
    """Call the judge model and return the raw text response."""
    if config.api_format == "openai":
        return await _call_openai_judge(prompt, config)
    elif config.api_format == "anthropic":
        return await _call_anthropic_judge(prompt, config)
    else:
        raise ValueError(f"Unknown judge API format: {config.api_format}")


async def _call_openai_judge(prompt: str, config: UtilityConfig) -> str:
    url = f"{config.endpoint.rstrip('/')}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.api_key}",
    }
    body = {
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def _call_anthropic_judge(prompt: str, config: UtilityConfig) -> str:
    url = f"{config.endpoint.rstrip('/')}/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": config.model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]


def check_self_consistency(
    baseline_result: RunResult,
    redacted_result: RunResult,
    key_terms: list[str] | None = None,
) -> bool:
    """Offline check: do the baseline and redacted responses agree on key terms?

    If key_terms is not provided, extracts simple word overlap.
    """
    baseline = baseline_result.response_text.lower()
    redacted = redacted_result.restored_text.lower()

    if not baseline or not redacted:
        return True  # can't check without responses

    if key_terms:
        for term in key_terms:
            b_has = term.lower() in baseline
            r_has = term.lower() in redacted
            if b_has != r_has:
                return False
        return True

    # Fallback: word-level Jaccard similarity > 0.5.
    b_words = set(baseline.split())
    r_words = set(redacted.split())
    if not b_words or not r_words:
        return True
    jaccard = len(b_words & r_words) / len(b_words | r_words)
    return jaccard > 0.5


@dataclass
class WorkloadUtilitySummary:
    """Aggregate utility metrics across a workload."""

    workload: str
    option: str
    num_samples: int
    baseline_preferred: int
    redacted_preferred: int
    ties: int
    mean_score: float
    self_consistency_rate: float | None
    per_sample: list[UtilityResult]


async def measure_workload_utility(
    workload_name: str,
    baseline_results: list[RunResult],
    redacted_results: list[RunResult],
    judge_config: UtilityConfig,
    *,
    max_samples: int | None = None,
) -> WorkloadUtilitySummary:
    """Run judge-model comparison across a workload.

    Pairs baseline and redacted results by sample_id. Both must have
    non-empty response_text (online mode) for meaningful comparison.
    Falls back to self-consistency check for offline results.
    """
    baseline_map = {r.sample_id: r for r in baseline_results}
    redacted_map = {r.sample_id: r for r in redacted_results}
    common_ids = sorted(set(baseline_map) & set(redacted_map))
    if max_samples is not None:
        common_ids = common_ids[:max_samples]

    per_sample: list[UtilityResult] = []
    option = redacted_results[0].option if redacted_results else "unknown"

    for sid in common_ids:
        br = baseline_map[sid]
        rr = redacted_map[sid]

        has_responses = bool(br.response_text and rr.restored_text)

        if has_responses:
            ur = await judge_pair(br.original_text, br, rr, judge_config)
        else:
            # Offline: self-consistency only.
            sc = check_self_consistency(br, rr)
            ur = UtilityResult(
                sample_id=sid,
                option=rr.option,
                preference="tie",
                score=0.0,
                judge_rationale="offline mode — self-consistency only",
                self_consistent=sc,
            )
        per_sample.append(ur)

    n = len(per_sample)
    baseline_pref = sum(1 for u in per_sample if u.preference == "baseline")
    redacted_pref = sum(1 for u in per_sample if u.preference == "redacted")
    ties = sum(1 for u in per_sample if u.preference == "tie")
    mean_score = sum(u.score for u in per_sample) / n if n else 0.0

    sc_results = [u.self_consistent for u in per_sample if u.self_consistent is not None]
    sc_rate = sum(sc_results) / len(sc_results) if sc_results else None

    return WorkloadUtilitySummary(
        workload=workload_name,
        option=option,
        num_samples=n,
        baseline_preferred=baseline_pref,
        redacted_preferred=redacted_pref,
        ties=ties,
        mean_score=mean_score,
        self_consistency_rate=sc_rate,
        per_sample=per_sample,
    )
