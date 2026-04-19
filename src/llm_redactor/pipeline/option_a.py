"""Option A — local-only routing.

Classifies requests as TRIVIAL (answerable locally) or COMPLEX
(requires cloud). Trivial requests are answered by the local model
and never leave the device — perfect privacy by construction.

Uses the same few-shot classifier approach as local-splitter's T1
stage, calling Ollama directly (no cross-project dependency).

Fail-open: if the classifier is unreachable or ambiguous, the request
is classified as COMPLEX and proceeds to the cloud pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

import httpx

Classification = Literal["TRIVIAL", "COMPLEX"]

_DECISION_RE = re.compile(r"\b(TRIVIAL|COMPLEX)\b", re.IGNORECASE)

CLASSIFIER_MESSAGES: list[dict[str, str]] = [
    {"role": "user", "content": "Classify: What is 2+2? Answer TRIVIAL or COMPLEX only."},
    {"role": "assistant", "content": "TRIVIAL"},
    {
        "role": "user",
        "content": (
            "Classify: Design a distributed consensus algorithm for a multi-region database. "
            "Answer TRIVIAL or COMPLEX only."
        ),
    },
    {"role": "assistant", "content": "COMPLEX"},
    {
        "role": "user",
        "content": (
            "Classify: Rename variable x to count. Answer TRIVIAL or COMPLEX only."
        ),
    },
    {"role": "assistant", "content": "TRIVIAL"},
    {
        "role": "user",
        "content": (
            "Classify: Refactor the auth module to support OAuth2 with PKCE flow across "
            "three services. Answer TRIVIAL or COMPLEX only."
        ),
    },
    {"role": "assistant", "content": "COMPLEX"},
    {
        "role": "user",
        "content": (
            "Classify: What does the len() function do in Python? "
            "Answer TRIVIAL or COMPLEX only."
        ),
    },
    {"role": "assistant", "content": "TRIVIAL"},
    {
        "role": "user",
        "content": (
            "Classify: Analyze the security implications of this authentication middleware "
            "and suggest improvements. Answer TRIVIAL or COMPLEX only."
        ),
    },
    {"role": "assistant", "content": "COMPLEX"},
]


@dataclass
class RouteResult:
    """Outcome of the Option A routing decision."""

    classification: Classification
    local_response: str  # non-empty only for TRIVIAL
    classifier_raw: str
    latency_ms: float


def _parse_classification(raw: str) -> Classification:
    match = _DECISION_RE.search(raw)
    if match:
        word = match.group(1).upper()
        if word == "TRIVIAL":
            return "TRIVIAL"
        if word == "COMPLEX":
            return "COMPLEX"
    return "COMPLEX"


async def classify(
    text: str,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
    timeout: float = 15.0,
) -> Classification:
    """Classify a request as TRIVIAL or COMPLEX using a local model."""
    messages = list(CLASSIFIER_MESSAGES)
    messages.append(
        {
            "role": "user",
            "content": f"Classify: {text[:500]} Answer TRIVIAL or COMPLEX only.",
        }
    )

    url = f"{endpoint.rstrip('/')}/api/chat"
    body = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 10},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            raw = data.get("message", {}).get("content", "")
            return _parse_classification(raw)
    except Exception:
        return "COMPLEX"


async def answer_locally(
    text: str,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
    timeout: float = 60.0,
) -> str:
    """Answer a request using the local model."""
    url = f"{endpoint.rstrip('/')}/api/chat"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "")


async def route(
    text: str,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
) -> RouteResult:
    """Classify and optionally answer locally.

    If TRIVIAL, answers with the local model (nothing leaves the device).
    If COMPLEX, returns empty local_response — caller should proceed to cloud.
    """
    import time

    t0 = time.perf_counter()

    classification = await classify(text, endpoint=endpoint, model=model)

    local_response = ""
    if classification == "TRIVIAL":
        local_response = await answer_locally(text, endpoint=endpoint, model=model)

    elapsed = (time.perf_counter() - t0) * 1000

    return RouteResult(
        classification=classification,
        local_response=local_response,
        classifier_raw=classification,
        latency_ms=elapsed,
    )
