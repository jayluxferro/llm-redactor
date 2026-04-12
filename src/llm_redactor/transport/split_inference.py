"""Option E — Split-inference transport stub.

Demonstrates the protocol shape of split (federated) inference where
the first and last transformer layers run locally while the middle
layers execute on a remote server.  Only intermediate activations
(hidden states) cross the network boundary, so the remote server
never sees raw tokens.

A production implementation would:
- Use Petals (https://github.com/bigscience-workshop/petals) or a
  similar library to load the first *k* and last *k* transformer
  blocks on the client GPU/CPU.
- Serialize the intermediate activation tensor (bfloat16, shape
  [batch, seq_len, hidden_dim]) and stream it to the remote swarm
  via libp2p or gRPC.
- The remote node runs the remaining middle layers and returns the
  resulting activation for the client to finish with the final
  layers + LM head.
- Privacy comes from the fact that reconstructing input tokens from
  mid-network activations is non-trivial (though not impossible —
  see "Sentence Embedding Leaks" literature).

This stub replaces real tensor ops with plain-Python list arithmetic
and sends the fake activations to a remote endpoint via HTTP.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class SplitInferenceResult:
    """Timing and shape metadata for one split-inference call."""

    local_layers: int
    remote_layers: int
    activation_shape: tuple[int, ...]
    latency_local_ms: float
    latency_remote_ms: float


async def split_forward_stub(
    token_ids: list[int],
    *,
    remote_url: str,
    local_layers: int = 4,
    remote_layers: int = 24,
    hidden_dim: int = 4096,
    timeout: float = 60.0,
) -> SplitInferenceResult:
    """Simulate a split-inference forward pass (stub).

    1. **Local prefix layers** — multiply random "weights" by the
       token-id vector to produce a fake activation tensor.
    2. **Remote middle layers** — POST the activation to *remote_url*.
    3. **Local suffix layers** — trivially pass through the returned
       activations (no real computation).

    Returns timing metadata; the actual logits/text are not produced
    because this is a protocol-shape demonstration only.
    """
    seq_len = len(token_ids)

    # --- local prefix layers (stub) ---
    t0 = time.perf_counter()
    activation = [
        [random.gauss(0, 0.02) for _ in range(hidden_dim)]
        for _ in range(seq_len)
    ]
    latency_local_ms = (time.perf_counter() - t0) * 1000

    # --- remote middle layers ---
    payload: dict[str, Any] = {
        "activation": activation,
        "start_layer": local_layers,
        "end_layer": local_layers + remote_layers,
    }
    t1 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(remote_url, json=payload)
            resp.raise_for_status()
    except httpx.HTTPError:
        pass  # stub — tolerate unreachable remote
    latency_remote_ms = (time.perf_counter() - t1) * 1000

    return SplitInferenceResult(
        local_layers=local_layers,
        remote_layers=remote_layers,
        activation_shape=(seq_len, hidden_dim),
        latency_local_ms=round(latency_local_ms, 2),
        latency_remote_ms=round(latency_remote_ms, 2),
    )
