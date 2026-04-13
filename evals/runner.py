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
from llm_redactor.transport.tee import verify_attestation
from llm_redactor.transport.split_inference import split_forward_stub
from llm_redactor.transport.fhe import fhe_classify_stub
from llm_redactor.transport.mpc import mpc_embedding_stub

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


async def run_option_d_offline(
    sample: Sample,
    *,
    attestation_url: str = "",
) -> RunResult:
    """Run Option D: TEE-hosted inference (stub).

    Outgoing text = original (TEE sees plaintext). Privacy comes from
    hardware attestation, not from redaction. If attestation_url is provided,
    attempt real attestation verification; otherwise skip (offline demo).
    """
    t0 = time.perf_counter()

    att_verified = False
    att_error: str | None = None
    if attestation_url:
        att = await verify_attestation(attestation_url)
        att_verified = att.verified
        att_error = att.error
    else:
        # Offline mode: assume attestation passes (demo).
        att_verified = True

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="D",
        original_text=sample.text,
        outgoing_text=sample.text,  # TEE sees everything
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_e_offline(
    sample: Sample,
    *,
    local_layers: int = 4,
    remote_layers: int = 24,
    hidden_dim: int = 4096,
) -> RunResult:
    """Run Option E: split inference (stub).

    Tokens never leave the device — only activations cross the wire.
    outgoing_text = "" for leak measurement (no tokens sent).
    """
    t0 = time.perf_counter()

    token_ids = [ord(c) for c in sample.text[:512]]

    result = await split_forward_stub(
        token_ids,
        remote_url="http://localhost:0/stub",  # unreachable; stub tolerates
        local_layers=local_layers,
        remote_layers=remote_layers,
        hidden_dim=hidden_dim,
    )

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="E",
        original_text=sample.text,
        outgoing_text="",  # tokens never sent
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_f_offline(
    sample: Sample,
    *,
    sensitivity_threshold: float = 0.5,
) -> RunResult:
    """Run Option F: FHE sensitivity classification (stub).

    Only ciphertext leaves the device. outgoing_text = "" for leak measurement.
    Latency includes simulated encrypt + FHE inference + decrypt (~5s total).
    """
    t0 = time.perf_counter()

    result = await fhe_classify_stub(
        sample.text,
        sensitivity_threshold=sensitivity_threshold,
    )

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="F",
        original_text=sample.text,
        outgoing_text="",  # only ciphertext sent
        response_text="",
        restored_text="",
        detections=[{"kind": "fhe_classification", "confidence": result.confidence,
                      "text": result.prediction, "source": "fhe"}],
        reverse_map={},
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_g_offline(
    sample: Sample,
    *,
    num_parties: int = 3,
    embedding_dim: int = 768,
) -> RunResult:
    """Run Option G: MPC embedding lookup (stub).

    Only secret shares leave to each party — no single party sees tokens.
    outgoing_text = "" for leak measurement.
    """
    t0 = time.perf_counter()

    token_ids = [ord(c) for c in sample.text[:128]]

    result = await mpc_embedding_stub(
        token_ids,
        num_parties=num_parties,
        embedding_dim=embedding_dim,
    )

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="G",
        original_text=sample.text,
        outgoing_text="",  # only shares sent
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=elapsed,
        mode="offline",
    )


async def run_option_bd_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
) -> RunResult:
    """Run Option B+D: redact spans, then forward to TEE.

    Outgoing text = redacted (same as B). The TEE provides additional
    hardware-level protection on top of redaction.
    """
    t0 = time.perf_counter()

    text = sample.text
    spans = detect_all(text, use_ner=use_ner)
    result = redact(text, spans)

    # Simulate TEE attestation check (~0ms in offline stub).

    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="B+D",
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


async def run_option_ab_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> RunResult:
    """Run Option A+B: classify, route locally if trivial, redact if complex.

    For leak measurement: if TRIVIAL, outgoing_text = "" (nothing sent).
    If COMPLEX, outgoing_text = redacted text (same as B).
    """
    t0 = time.perf_counter()

    text = sample.text
    classification = await classify(
        text, endpoint=ollama_endpoint, model=ollama_model,
    )

    if classification == "TRIVIAL":
        elapsed = (time.perf_counter() - t0) * 1000
        return RunResult(
            sample_id=sample.id,
            option="A+B(local)",
            original_text=text,
            outgoing_text="",
            response_text="",
            restored_text="",
            detections=[],
            reverse_map={},
            latency_ms=elapsed,
            mode="offline",
        )

    # COMPLEX: apply Option B redaction.
    spans = detect_all(text, use_ner=use_ner)
    result = redact(text, spans)
    elapsed = (time.perf_counter() - t0) * 1000

    return RunResult(
        sample_id=sample.id,
        option="A+B(cloud)",
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


async def run_option_abc_offline(
    sample: Sample,
    *,
    use_ner: bool = False,
    ollama_endpoint: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2:3b",
) -> RunResult:
    """Run Option A+B+C: classify, route locally if trivial, redact+rephrase if complex."""
    t0 = time.perf_counter()

    text = sample.text
    classification = await classify(
        text, endpoint=ollama_endpoint, model=ollama_model,
    )

    if classification == "TRIVIAL":
        elapsed = (time.perf_counter() - t0) * 1000
        return RunResult(
            sample_id=sample.id,
            option="A+B+C(local)",
            original_text=text,
            outgoing_text="",
            response_text="",
            restored_text="",
            detections=[],
            reverse_map={},
            latency_ms=elapsed,
            mode="offline",
        )

    # COMPLEX: apply B then C.
    spans = detect_all(text, use_ner=use_ner)
    redaction_result = redact(text, spans)

    rr = await rephrase_text(
        redaction_result.redacted_text,
        endpoint=ollama_endpoint,
        model=ollama_model,
    )
    vr = validate_rephrase(redaction_result.redacted_text, rr.rephrased_text)

    if vr.valid:
        outgoing = rr.rephrased_text
        option_label = "A+B+C(cloud)"
    else:
        outgoing = redaction_result.redacted_text
        option_label = "A+B(cloud,C-rejected)"

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
    max_samples: int | None = None,
) -> list[RunResult]:
    """Run all samples in a workload through the specified option.

    Returns a list of RunResult, one per sample.
    """
    samples = read_workload(workload_path)
    if max_samples is not None:
        samples = samples[:max_samples]
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
        elif option == "D":
            result = asyncio.run(run_option_d_offline(sample))
            results.append(result)
        elif option == "E":
            result = asyncio.run(run_option_e_offline(sample))
            results.append(result)
        elif option == "F":
            result = asyncio.run(run_option_f_offline(sample))
            results.append(result)
        elif option == "G":
            result = asyncio.run(run_option_g_offline(sample))
            results.append(result)
        elif option == "B+D":
            result = asyncio.run(
                run_option_bd_offline(sample, use_ner=use_ner)
            )
            results.append(result)
        elif option == "A+B":
            result = asyncio.run(
                run_option_ab_offline(
                    sample, use_ner=use_ner,
                    ollama_endpoint=ollama_endpoint, ollama_model=ollama_model,
                )
            )
            results.append(result)
        elif option == "A+B+C":
            result = asyncio.run(
                run_option_abc_offline(
                    sample, use_ner=use_ner,
                    ollama_endpoint=ollama_endpoint, ollama_model=ollama_model,
                )
            )
            results.append(result)
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
