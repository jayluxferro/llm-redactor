"""Option D — Trusted Execution Environment (TEE) transport client.

Verifies remote attestation of a TEE-hosted inference endpoint, then
forwards plaintext prompts only after the attestation check passes.

A production implementation would:
- Parse the attestation document as a COSE Sign1 structure (CBOR).
- Verify the signature chain up to the AWS Nitro Enclaves root
  certificate (or the equivalent for AMD SEV-SNP / Intel TDX).
- Validate PCR values (PCR0 = enclave image, PCR1 = kernel,
  PCR2 = application) against known-good measurements published
  by the model provider.
- Check the attestation document nonce to prevent replay attacks.
- Optionally pin the TLS certificate to the one embedded in the
  attestation document (aTLS / attested TLS).

This stub verifies only that the attestation endpoint returns HTTP 200
with the expected JSON fields, which is sufficient for the paper demo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class AttestationResult:
    """Outcome of a remote-attestation verification."""

    verified: bool
    pcr_values: dict[str, str] = field(default_factory=dict)
    enclave_id: str = ""
    error: str | None = None


async def verify_attestation(
    attestation_url: str,
    *,
    timeout: float = 10.0,
) -> AttestationResult:
    """Fetch and verify a remote attestation document (stub).

    In a real deployment this function would:
    1. Retrieve the CBOR-encoded attestation document from *attestation_url*.
    2. Decode the COSE Sign1 envelope and extract the document payload.
    3. Walk the x5c certificate chain back to the AWS Nitro root CA
       (or AMD / Intel root for SEV-SNP / TDX).
    4. Compare PCR0-2 against the expected measurements for the model
       image and runtime.
    5. Verify the nonce/challenge to prevent replay.

    The stub simply checks that the endpoint returns 200 with JSON
    containing ``enclave_id`` and ``pcr_values``.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(attestation_url)
            resp.raise_for_status()
            doc = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return AttestationResult(verified=False, error=str(exc))

    enclave_id = doc.get("enclave_id", "")
    pcr_values = doc.get("pcr_values", {})

    if not enclave_id or not pcr_values:
        return AttestationResult(
            verified=False,
            error="Attestation response missing enclave_id or pcr_values",
        )

    return AttestationResult(
        verified=True,
        pcr_values=pcr_values,
        enclave_id=enclave_id,
    )


async def forward_to_tee(
    body: dict[str, Any],
    *,
    attestation_url: str,
    inference_url: str,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Verify attestation, then forward a chat-completion request.

    Raises ``RuntimeError`` if attestation fails.
    Raises ``httpx.HTTPStatusError`` on non-2xx inference responses.
    """
    att = await verify_attestation(attestation_url)
    if not att.verified:
        raise RuntimeError(f"TEE attestation failed: {att.error}")

    url = f"{inference_url.rstrip('/')}/chat/completions"
    headers = {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()

    result["_tee_attestation"] = {
        "enclave_id": att.enclave_id,
        "pcr_values": att.pcr_values,
    }
    return result
