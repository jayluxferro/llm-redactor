"""Evaluation runner — runs a single option on a single workload.

Modes:
  - offline: detect + redact only, capture outgoing text for leak measurement.
    No cloud call. Fast, deterministic, no API key needed.
  - online: full pipeline including cloud call. Needed for utility measurement.

Emits a RunResult per sample, which can be written to JSONL.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from llm_redactor.config import Config
from llm_redactor.detect.orchestrator import detect_all
from llm_redactor.detect.types import Span
from llm_redactor.redact.placeholder import redact
from llm_redactor.redact.restore import restore
from llm_redactor.noise.dp import inject_noise
from llm_redactor.pipeline.option_a import classify
from llm_redactor.rephrase.local_model import rephrase as rephrase_text
from llm_redactor.rephrase.validator import validate_rephrase

from .schema import Sample, read_workload


@dataclass
class RunResult:
    """Result of running one sample through one option."""

    sample_id: str
    option: str
    original_text: str
    outgoing_text: str  # what the cloud would see
    response_text: str  # cloud response (empty in offline mode)
    restored_text: str  # response after restoration (empty in offline)
    detections: list[dict[str, Any]]
    reverse_map: dict[str, str]
    latency_ms: float
    mode: str  # "offline" or "online"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunResult:
        return cls(**d)


def run_option_b_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
) -> RunResult:
    """Run Option B detection + redaction without a cloud call.

    Returns the outgoing text (what the cloud would see) for leak measurement.
    """
    t0 = time.perf_counter()

    text = sample.text
    spans = detect_all(text, use_ner=use_ner)
    result = redact(text, spans)

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="B",
        original_text=text,
        outgoing_text=result.redacted_text,
        response_text="",
        restored_text="",
        detections=[
            {"kind": s.kind, "confidence": s.confidence, "text": s.text, "source": s.source}
            for s in spans
        ],
        reverse_map=result.reverse_map,
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_b_online(
    sample: Sample,
    config: Config,
    *,
    use_ner: bool = False,
    model: str = "gpt-4o-mini",
) -> RunResult:
    """Run Option B full pipeline with a real cloud call."""
    from llm_redactor.transport.cloud import forward_chat_completion

    t0 = time.perf_counter()

    text = sample.text
    spans = detect_all(text, use_ner=use_ner)
    redaction_result = redact(text, spans)

    body = {
        "model": model,
        "messages": [{"role": "user", "content": redaction_result.redacted_text}],
    }

    cloud_response = await forward_chat_completion(body, config.cloud_target)

    response_text = ""
    if "choices" in cloud_response and cloud_response["choices"]:
        response_text = cloud_response["choices"][0].get("message", {}).get("content", "")

    restored_text = restore(response_text, redaction_result.reverse_map)

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="B",
        original_text=text,
        outgoing_text=redaction_result.redacted_text,
        response_text=response_text,
        restored_text=restored_text,
        detections=[
            {"kind": s.kind, "confidence": s.confidence, "text": s.text, "source": s.source}
            for s in spans
        ],
        reverse_map=redaction_result.reverse_map,
        latency_ms=elapsed,
        mode="online",
    )


async def run_option_bc_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> RunResult:
    """Run Option B+C: redact spans, then rephrase via local model.

    Offline = no cloud call, but does call the local Ollama model for rephrasing.
    Returns the outgoing text (post-rephrase) for leak measurement.
    """
    t0 = time.perf_counter()

    text = sample.text
    spans = detect_all(text, use_ner=use_ner)
    redaction_result = redact(text, spans)

    # Rephrase the redacted text.
    rr = await rephrase_text(
        redaction_result.redacted_text,
        endpoint=ollama_endpoint,
        model=ollama_model,
    )

    # Validate.
    vr = validate_rephrase(redaction_result.redacted_text, rr.rephrased_text)

    if vr.valid:
        outgoing = rr.rephrased_text
        option_label = "B+C"
    else:
        # Rollback to B-only.
        outgoing = redaction_result.redacted_text
        option_label = "B(C-rejected)"

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option=option_label,
        original_text=text,
        outgoing_text=outgoing,
        response_text="",
        restored_text="",
        detections=[
            {"kind": s.kind, "confidence": s.confidence, "text": s.text, "source": s.source}
            for s in spans
        ],
        reverse_map=redaction_result.reverse_map,
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_a_offline(
    sample: Sample,
    *,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> RunResult:
    """Run Option A: classify as TRIVIAL/COMPLEX.

    For leak measurement: if TRIVIAL, outgoing_text is empty (nothing sent
    to cloud). If COMPLEX, outgoing_text is the original (would go to cloud
    or a downstream option).
    """
    t0 = time.perf_counter()

    classification = await classify(
        sample.text, endpoint=ollama_endpoint, model=ollama_model,
    )

    elapsed = (time.perf_counter() - t0) * 1000

    if classification == "TRIVIAL":
        # Nothing leaves the device. Perfect privacy.
        return RunResult(
            sample_id=sample.id,
            option="A(local)",
            original_text=sample.text,
            outgoing_text="",  # nothing sent to cloud
            response_text="",
            restored_text="",
            detections=[],
            reverse_map={},
            latency_ms=elapsed,
            mode="offline",
        )
    else:
        # Would proceed to cloud — outgoing is the original text.
        return RunResult(
            sample_id=sample.id,
            option="A(cloud)",
            original_text=sample.text,
            outgoing_text=sample.text,
            response_text="",
            restored_text="",
            detections=[],
            reverse_map={},
            latency_ms=elapsed,
            mode="offline",
        )


def run_option_bh_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
    epsilon: float = 4.0,
) -> RunResult:
    """Run Option B+H: redact spans, then add DP noise.

    Deterministic (seeded by content hash). No cloud or Ollama call.
    """
    t0 = time.perf_counter()

    text = sample.text
    spans = detect_all(text, use_ner=use_ner)
    redaction_result = redact(text, spans)

    # Apply DP noise to the redacted text.
    dp_result = inject_noise(
        redaction_result.redacted_text,
        epsilon=epsilon,
        seed=hash(text) & 0xFFFFFFFF,
    )

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option=f"B+H(e={epsilon})",
        original_text=text,
        outgoing_text=dp_result.noised_text,
        response_text="",
        restored_text="",
        detections=[
            {"kind": s.kind, "confidence": s.confidence, "text": s.text, "source": s.source}
            for s in spans
        ],
        reverse_map=redaction_result.reverse_map,
        latency_ms=elapsed,
        mode="offline",
    )


def run_baseline(sample: Sample) -> RunResult:
    """Baseline: no redaction. The cloud sees everything.

    Used for leak rate = 100% comparison and utility baseline.
    """
    return RunResult(
        sample_id=sample.id,
        option="baseline",
        original_text=sample.text,
        outgoing_text=sample.text,
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=0.0,
        mode="offline",
    )


def run_workload(
    workload_path: Path,
    option: str = "B",
    *,
    use_ner: bool = False,
    mode: str = "offline",
    config: Config | None = None,
    model: str = "gpt-4o-mini",
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
    epsilon: float = 4.0,
) -> list[RunResult]:
    """Run all samples in a workload through the specified option.

    Returns a list of RunResult, one per sample.
    """
    samples = read_workload(workload_path)
    results: list[RunResult] = []

    for sample in samples:
        if option == "baseline":
            results.append(run_baseline(sample))
        elif option == "A":
            result = asyncio.run(
                run_option_a_offline(
                    sample, ollama_endpoint=ollama_endpoint, ollama_model=ollama_model,
                )
            )
            results.append(result)
        elif option == "B" and mode == "offline":
            results.append(run_option_b_offline(sample, use_ner=use_ner))
        elif option == "B" and mode == "online":
            if config is None:
                raise ValueError("Config required for online mode")
            result = asyncio.run(
                run_option_b_online(sample, config, use_ner=use_ner, model=model)
            )
            results.append(result)
        elif option == "B+C":
            result = asyncio.run(
                run_option_bc_offline(
                    sample,
                    use_ner=use_ner,
                    ollama_endpoint=ollama_endpoint,
                    ollama_model=ollama_model,
                )
            )
            results.append(result)
        elif option == "B+H":
            results.append(
                run_option_bh_offline(sample, use_ner=use_ner, epsilon=epsilon)
            )
        else:
            raise ValueError(f"Unsupported option={option} mode={mode}")

    return results


def write_results(results: list[RunResult], path: Path) -> None:
    """Write run results to JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in results:
            f.write(json.dumps(r.to_dict()) + "\n")


def read_results(path: Path) -> list[RunResult]:
    """Read run results from JSONL."""
    results = []
    with open(path) as f:
        for line in f:
            if line.strip():
                results.append(RunResult.from_dict(json.loads(line)))
    return results
