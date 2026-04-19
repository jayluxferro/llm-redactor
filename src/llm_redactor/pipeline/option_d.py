"""Option D pipeline: verify TEE attestation → forward plaintext to enclave.

The TEE sees the full plaintext, but hardware attestation guarantees that
the data never leaves the enclave boundary.  Privacy comes from the TEE's
isolation, not from redaction.

For evaluation: outgoing_text = original (the TEE sees everything).  The
paper reports this as 100% wire leak but distinguishes it from options
where an untrusted cloud sees plaintext.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..transport.tee import AttestationResult, forward_to_tee, verify_attestation


@dataclass
class OptionDPipelineResult:
    """Result of running Option D on a chat completion request."""

    response: dict[str, Any]
    attestation: AttestationResult
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionDPipeline:
    """Option D: forward to TEE-hosted inference after attestation."""

    config: Config
    _stats: dict[str, int] = field(
        default_factory=lambda: {
            "requests": 0,
            "attestation_failures": 0,
        }
    )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionDPipelineResult:
        """Verify attestation and forward the request to the TEE endpoint."""
        self._stats["requests"] += 1

        attestation_url = self.config.pipeline.opt_d_tee.attestation_url
        inference_url = self.config.pipeline.opt_d_tee.inference_url

        # Verify attestation first.
        att = await verify_attestation(attestation_url)
        if not att.verified:
            self._stats["attestation_failures"] += 1
            raise TEEAttestationError(att.error or "Attestation verification failed")

        # Forward plaintext to TEE.
        cloud_response = await forward_to_tee(
            body,
            attestation_url=attestation_url,
            inference_url=inference_url,
        )

        outgoing_text = " ".join(
            m.get("content", "")
            for m in body.get("messages", [])
            if isinstance(m.get("content"), str)
        )

        return OptionDPipelineResult(
            response=cloud_response,
            attestation=att,
            options_applied=["D"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "tee_protected": True,
                "enclave_id": att.enclave_id,
            },
        )


class TEEAttestationError(Exception):
    """Raised when TEE attestation verification fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"TEE attestation failed: {reason}")
