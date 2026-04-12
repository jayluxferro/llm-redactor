"""Local Ollama-based rewriting for Option C.

Sends text to a local model with a privacy-stripping prompt.
The model rewrites the text to remove identifying details while
preserving the technical question.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

SYSTEM_PROMPT = """\
You are a privacy-preserving rewriter. Your job is to rewrite the user's \
text so that it no longer identifies any specific person, organisation, \
team, project, product, or location — while preserving the technical \
meaning so that a helpful AI assistant could still answer the question.

Rules:
1. Replace real names with generic labels (e.g. "a senior engineer", \
"the company", "the team").
2. Replace project codenames, product names, and internal identifiers \
with generic descriptions of what they are.
3. Replace company names with "the company" or "a tech company" etc.
4. Replace team names with "the team" or a generic descriptor.
5. Keep all technical terms, programming languages, frameworks, error \
messages, code patterns, and domain concepts intact.
6. Keep the structure and intent of the original text.
7. Do NOT add new information or hallucinate details.
8. Do NOT explain what you changed. Just output the rewritten text.
9. If the text contains no identifying information, return it unchanged.

Output ONLY the rewritten text, nothing else."""

USER_PROMPT_TEMPLATE = "Rewrite the following text to remove identifying information:\n\n{text}"


@dataclass
class RephraseResult:
    """Result of a local-model rephrase."""

    original_text: str
    rephrased_text: str
    model: str
    prompt_tokens: int
    completion_tokens: int


async def rephrase(
    text: str,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
    temperature: float = 0.3,
    timeout: float = 60.0,
) -> RephraseResult:
    """Rephrase text using a local Ollama model to strip identifying details."""
    url = f"{endpoint.rstrip('/')}/api/chat"

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(text=text)},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
        },
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()

    rephrased = data.get("message", {}).get("content", "").strip()
    prompt_tokens = data.get("prompt_eval_count", 0)
    completion_tokens = data.get("eval_count", 0)

    return RephraseResult(
        original_text=text,
        rephrased_text=rephrased,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def rephrase_sync(
    text: str,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "llama3.2:3b",
    temperature: float = 0.3,
    timeout: float = 60.0,
) -> RephraseResult:
    """Synchronous wrapper for rephrase()."""
    import asyncio

    return asyncio.run(
        rephrase(text, endpoint=endpoint, model=model, temperature=temperature, timeout=timeout)
    )
