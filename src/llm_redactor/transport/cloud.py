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
    upstream_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Forward an OpenAI-compatible chat completion request to the cloud target.

    Returns the parsed JSON response.
    Raises httpx.HTTPStatusError on non-2xx responses.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/chat/completions"

    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if api_key and "authorization" not in headers:
        headers["Authorization"] = f"Bearer {api_key}"

    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        return _parse_json_response(resp, url)


def _parse_json_response(resp: httpx.Response, url: str) -> dict[str, Any]:
    """Parse JSON from an upstream response, with a clear error on failure."""
    try:
        return resp.json()
    except Exception:
        try:
            text = resp.text[:1024] if resp.text else "(empty body)"
        except Exception:
            text = f"(undecodable body, {len(resp.content)} bytes)"
        raise httpx.HTTPStatusError(
            message=f"Upstream returned non-JSON response: {text}",
            request=resp.request,
            response=resp,
        )


async def forward_chat_completion_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
    upstream_headers: dict[str, str] | None = None,
) -> AsyncIterator[bytes]:
    """Forward a streaming chat completion request and yield raw SSE chunks.

    The caller is responsible for parsing and restoring placeholders
    in the content deltas.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/chat/completions"

    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if api_key and "authorization" not in headers:
        headers["Authorization"] = f"Bearer {api_key}"

    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        async with client.stream("POST", url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk


async def forward_anthropic_messages(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
    upstream_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Forward an Anthropic Messages API request.

    Expects body with {model, messages, max_tokens, ...}.
    Uses x-api-key header instead of Bearer token.
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    # Start with forwarded headers, then overlay service essentials.
    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key

    # Pass original user-agent on the client so httpx never injects its own
    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        return _parse_json_response(resp, url)


async def forward_anthropic_raw(
    body_bytes: bytes,
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
    upstream_headers: dict[str, str] | None = None,
) -> tuple[bytes, int, dict[str, str]]:
    """Forward raw request bytes to the Anthropic Messages endpoint.

    Used when the request contains ``thinking`` or ``redacted_thinking``
    blocks whose signatures Anthropic validates against the exact JSON
    encoding it served — any json.loads/dumps round-trip breaks them.

    Returns (body_bytes, status_code, response_headers).
    """
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key

    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        resp = await client.post(url, content=body_bytes, headers=headers)
        return resp.content, resp.status_code, dict(resp.headers)


async def forward_anthropic_raw_stream(
    body_bytes: bytes,
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
    upstream_headers: dict[str, str] | None = None,
) -> AsyncIterator[bytes]:
    """Stream variant of :func:`forward_anthropic_raw`."""
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key

    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        async with client.stream("POST", url, content=body_bytes, headers=headers) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk


async def forward_anthropic_messages_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: float = 120.0,
    upstream_headers: dict[str, str] | None = None,
) -> AsyncIterator[bytes]:
    """Forward a streaming Anthropic Messages request and yield raw SSE chunks."""
    api_key = os.environ.get(config.api_key_env, "")
    url = f"{config.endpoint.rstrip('/')}/messages"

    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key

    # Pass original user-agent on the client so httpx never injects its own
    client_ua = headers.pop("user-agent", None)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    ) as client:
        async with client.stream("POST", url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk
