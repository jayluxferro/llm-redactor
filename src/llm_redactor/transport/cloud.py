"""Standard cloud API router (OpenAI-compatible POST) + Anthropic Messages API."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
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


async def forward_chat_completion_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
) -> AsyncIterator[bytes]:
    """Forward a streaming chat completion request and yield raw SSE chunks.

    The caller is responsible for parsing and restoring placeholders
    in the content deltas.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/chat/completions"

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk


async def forward_anthropic_messages(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Forward an Anthropic Messages API request.

    Expects body with {model, messages, max_tokens, ...}.
    Uses x-api-key header instead of Bearer token.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    if api_key:
        headers["x-api-key"] = api_key

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()


async def forward_anthropic_messages_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
) -> AsyncIterator[bytes]:
    """Forward a streaming Anthropic Messages request and yield raw SSE chunks."""
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    if api_key:
        headers["x-api-key"] = api_key

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk
