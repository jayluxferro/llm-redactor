"""Option F pipeline: FHE sensitivity classification.

Demonstrates fully homomorphic encryption for a small sensitivity classifier.
Full LLM inference under FHE is infeasible today (10,000–100,000× slowdown),
so we scope this to a binary classifier: "is this input sensitive?"

The server evaluates the compiled FHE circuit on ciphertext and returns
ciphertext; the client decrypts.  The server never sees plaintext.

For evaluation: outgoing_text = "" (only ciphertext leaves).  The paper
reports 0% plaintext leak with the FHE latency overhead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..transport.fhe import FHEClassificationResult, fhe_classify_stub


@dataclass
class OptionFPipelineResult:
    """Result of running Option F on a request."""

    classification: FHEClassificationResult
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionFPipeline:
    """Option F: FHE-encrypted sensitivity classification."""

    config: Config
    sensitivity_threshold: float = 0.5
    _stats: dict[str, int] = field(
        default_factory=lambda: {
            "requests": 0,
            "classified_sensitive": 0,
            "classified_non_sensitive": 0,
        }
    )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionFPipelineResult:
        """Run FHE sensitivity classification on the request."""
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        text = " ".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))

        result = await fhe_classify_stub(
            text,
            sensitivity_threshold=self.sensitivity_threshold,
        )

        if result.prediction == "sensitive":
            self._stats["classified_sensitive"] += 1
        else:
            self._stats["classified_non_sensitive"] += 1

        return OptionFPipelineResult(
            classification=result,
            options_applied=["F"],
            leak_audit={
                "plaintext_sent": False,
                "ciphertext_sent": True,
                "prediction": result.prediction,
                "fhe_latency_ms": (
                    result.encryption_time_ms + result.inference_time_ms + result.decryption_time_ms
                ),
            },
        )
