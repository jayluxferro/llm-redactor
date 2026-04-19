"""Option E pipeline: split inference — local prefix layers + remote middle layers.

Tokens never leave the device.  Only intermediate activation tensors cross the
network boundary.  Privacy comes from the difficulty of inverting mid-network
activations back to input tokens (though this is not impossible — see
"Sentence Embedding Leaks" literature).

For evaluation: outgoing_text = "" (no tokens sent).  The paper reports this as
0% token leak but discusses the activation-inversion residual risk separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..transport.split_inference import SplitInferenceResult, split_forward_stub


@dataclass
class OptionEPipelineResult:
    """Result of running Option E on a request."""

    split_result: SplitInferenceResult
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionEPipeline:
    """Option E: split inference with local prefix/suffix layers."""

    config: Config
    local_layers: int = 4
    remote_layers: int = 24
    hidden_dim: int = 4096
    _stats: dict[str, int] = field(
        default_factory=lambda: {
            "requests": 0,
        }
    )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionEPipelineResult:
        """Run split inference on the request."""
        self._stats["requests"] += 1

        # Extract text to compute token IDs (simplified: char-level).
        messages = body.get("messages", [])
        text = " ".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))
        # Stub tokenisation: use character codes.
        token_ids = [ord(c) for c in text[:512]]

        remote_url = self.config.pipeline.opt_e_split.remote_url

        result = await split_forward_stub(
            token_ids,
            remote_url=remote_url,
            local_layers=self.local_layers,
            remote_layers=self.remote_layers,
            hidden_dim=self.hidden_dim,
        )

        return OptionEPipelineResult(
            split_result=result,
            options_applied=["E"],
            leak_audit={
                "tokens_sent": 0,  # tokens never leave
                "activations_sent": True,
                "activation_shape": result.activation_shape,
                "local_layers": result.local_layers,
                "remote_layers": result.remote_layers,
            },
        )
