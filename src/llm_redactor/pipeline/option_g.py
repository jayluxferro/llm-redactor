"""Option G pipeline: MPC embedding lookup.

Demonstrates secure multi-party computation for the token-embedding stage.
Input token IDs are secret-shared across N parties; each party holds a shard
of the embedding table and performs an oblivious lookup.  No single party
sees the full input or the full embedding.

For evaluation: outgoing_text = "" (only secret shares leave).  The paper
reports 0% single-party token leak with the MPC latency overhead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..transport.mpc import MPCEmbeddingResult, mpc_embedding_stub


@dataclass
class OptionGPipelineResult:
    """Result of running Option G on a request."""

    mpc_result: MPCEmbeddingResult
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionGPipeline:
    """Option G: MPC embedding lookup across N parties."""

    config: Config
    num_parties: int = 3
    embedding_dim: int = 768
    _stats: dict[str, int] = field(default_factory=lambda: {
        "requests": 0,
    })

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionGPipelineResult:
        """Run MPC embedding lookup on the request."""
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        text = " ".join(
            m.get("content", "")
            for m in messages
            if isinstance(m.get("content"), str)
        )
        # Stub tokenisation: character codes, capped for MPC latency.
        token_ids = [ord(c) for c in text[:128]]

        result = await mpc_embedding_stub(
            token_ids,
            num_parties=self.num_parties,
            embedding_dim=self.embedding_dim,
        )

        return OptionGPipelineResult(
            mpc_result=result,
            options_applied=["G"],
            leak_audit={
                "tokens_sent": 0,
                "shares_sent_per_party": len(token_ids),
                "num_parties": result.num_parties,
                "collusion_threshold": result.num_parties,  # additive: all must collude
            },
        )
