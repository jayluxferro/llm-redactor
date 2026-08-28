"""Standard cloud API router (OpenAI-compatible POST) + Anthropic Messages API."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import CloudTargetConfig

# Structured upstream timeout. A single flat float applies the same deadline
# to connect, read, write, and pool — a non-streaming LLM call that takes
# longer than that to produce its first byte dies with httpx.ReadTimeout even
# though the upstream is healthy and working. Separate the phases: connect
# fails fast, read gets a generous window (non-streaming responses send
# nothing until generation completes; streaming resets the clock per chunk).
DEFAULT_UPSTREAM_TIMEOUT: httpx.Timeout = httpx.Timeout(
    connect=10.0,
    read=600.0,
    write=60.0,
    pool=10.0,
)


@dataclass
class StreamResult:
    """Upstream response preflight for streaming endpoints.

    Gate 1 pattern: open the upstream stream, read its headers, and decide
    whether to pass through as SSE or return a faithful plain response.
    """

    status_code: int
    content_type: str | None
    headers: dict[str, str]
    body: bytes | None = None
    iterator: AsyncIterator[bytes] | None = None

    def is_sse(self) -> bool:
        return bool(self.content_type) and "text/event-stream" in (self.content_type or "")


async def forward_chat_completion(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
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


def _build_openai_request(
    client: httpx.AsyncClient,
    body: dict[str, Any],
    config: CloudTargetConfig,
    upstream_headers: dict[str, str] | None = None,
) -> httpx.Request:
    url = f"{config.endpoint.rstrip('/')}/chat/completions"
    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    api_key = os.environ.get(config.api_key_env, "")
    if api_key and "authorization" not in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    return client.build_request("POST", url, json=body, headers=headers)


def _build_anthropic_request(
    client: httpx.AsyncClient,
    config: CloudTargetConfig,
    *,
    json: dict[str, Any] | None = None,
    content: bytes | None = None,
    upstream_headers: dict[str, str] | None = None,
) -> httpx.Request:
    url = f"{config.endpoint.rstrip('/')}/messages"
    headers: dict[str, str] = dict(upstream_headers) if upstream_headers else {}
    headers["content-type"] = "application/json"
    if "anthropic-version" not in headers:
        headers["anthropic-version"] = "2023-06-01"
    api_key = os.environ.get(config.api_key_env, "")
    if api_key and "x-api-key" not in headers and "authorization" not in headers:
        headers["x-api-key"] = api_key
    if json is not None:
        return client.build_request("POST", url, json=json, headers=headers)
    return client.build_request("POST", url, content=content, headers=headers)


async def _close_on_error(resp: httpx.Response, client: httpx.AsyncClient) -> bytes:
    body = await resp.aread()
    await resp.aclose()
    await client.aclose()
    return body


def _stream_response(resp: httpx.Response, client: httpx.AsyncClient) -> AsyncIterator[bytes]:
    """Yield raw upstream bytes and ensure response/client cleanup."""

    async def gen() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()
            await client.aclose()

    return gen()


async def forward_chat_completion_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
    upstream_headers: dict[str, str] | None = None,
) -> StreamResult:
    """Forward a streaming chat completion request and return a preflight result.

    Gate 1: opens the upstream stream and returns either a faithful plain
    response (for non-2xx or non-SSE upstreams) or an iterator of raw SSE
    chunks.  The caller commits to ``text/event-stream`` only after this check.
    """
    client_ua = ""
    if upstream_headers:
        client_ua = upstream_headers.get("user-agent", "")
    client = httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    )
    req = _build_openai_request(client, body, config, upstream_headers)
    resp = await client.send(req, stream=True)
    content_type = resp.headers.get("content-type")
    if resp.status_code >= 400 or "text/event-stream" not in (content_type or ""):
        body_bytes = await _close_on_error(resp, client)
        return StreamResult(
            status_code=resp.status_code,
            content_type=content_type,
            headers=dict(resp.headers),
            body=body_bytes,
        )
    return StreamResult(
        status_code=resp.status_code,
        content_type=content_type,
        headers=dict(resp.headers),
        iterator=_stream_response(resp, client),
    )


async def forward_anthropic_messages(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
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
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
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
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
    upstream_headers: dict[str, str] | None = None,
) -> StreamResult:
    """Stream variant of :func:`forward_anthropic_raw` with Gate 1 preflight."""
    client_ua = ""
    if upstream_headers:
        client_ua = upstream_headers.get("user-agent", "")
    client = httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    )
    req = _build_anthropic_request(
        client, config, content=body_bytes, upstream_headers=upstream_headers
    )
    resp = await client.send(req, stream=True)
    content_type = resp.headers.get("content-type")
    if resp.status_code >= 400 or "text/event-stream" not in (content_type or ""):
        body_bytes = await _close_on_error(resp, client)
        return StreamResult(
            status_code=resp.status_code,
            content_type=content_type,
            headers=dict(resp.headers),
            body=body_bytes,
        )
    return StreamResult(
        status_code=resp.status_code,
        content_type=content_type,
        headers=dict(resp.headers),
        iterator=_stream_response(resp, client),
    )


async def forward_anthropic_messages_stream(
    body: dict[str, Any],
    config: CloudTargetConfig,
    *,
    timeout: httpx.Timeout = DEFAULT_UPSTREAM_TIMEOUT,
    upstream_headers: dict[str, str] | None = None,
) -> StreamResult:
    """Forward a streaming Anthropic Messages request with Gate 1 preflight."""
    client_ua = ""
    if upstream_headers:
        client_ua = upstream_headers.get("user-agent", "")
    client = httpx.AsyncClient(
        timeout=timeout,
        headers={"user-agent": client_ua} if client_ua else {},
    )
    req = _build_anthropic_request(client, config, json=body, upstream_headers=upstream_headers)
    resp = await client.send(req, stream=True)
    content_type = resp.headers.get("content-type")
    if resp.status_code >= 400 or "text/event-stream" not in (content_type or ""):
        body_bytes = await _close_on_error(resp, client)
        return StreamResult(
            status_code=resp.status_code,
            content_type=content_type,
            headers=dict(resp.headers),
            body=body_bytes,
        )
    return StreamResult(
        status_code=resp.status_code,
        content_type=content_type,
        headers=dict(resp.headers),
        iterator=_stream_response(resp, client),
    )
