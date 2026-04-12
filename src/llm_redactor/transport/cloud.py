"""Standard cloud API router (OpenAI-compatible POST)."""

from __future__ import annotations

import os
from typing import Any

import httpx

from ..config import CloudTargetConfig


async def forward_chat_completion(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Forward an OpenAI-compatible chat completion request to the cloud target.

    Returns the parsed JSON response.
    Raises httpx.HTTPStatusError on non-2xx responses.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/chat/completions"

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
