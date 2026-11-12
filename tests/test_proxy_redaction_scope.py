"""Regression tests for what the proxy redacts and restores.

Each test pins a hole that existed before (see the commit that added this
file): unredacted system / tool_result / tool_use / count_tokens / content
parts, Anthropic streams that never restored placeholders, OpenAI streams
that garbled any placeholder split across deltas or any SSE line split
across network chunks, and upstream errors that surfaced as bare 500s.
All upstreams are stubbed; nothing leaves the test process.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.detect.orchestrator import detect_all
from llm_redactor.redact.placeholder import PlaceholderGenerator
from llm_redactor.redact.raw_surgery import SSETextRestorer, redact_signed_request
from llm_redactor.redact.restore import StreamRestorer
from llm_redactor.transport.cloud import StreamResult
from llm_redactor.transport.http_proxy import app, configure

EMAIL = "bob@corp.example"
AWS = "AKIAIOSFODNN7EXAMPLE"
PH = "⟨EMAIL_1⟩"


@pytest.fixture
def client() -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    configure(cfg, use_ner=False)
    return TestClient(app)


def _stream(*parts: bytes):
    async def fake(*_a: Any, **_k: Any) -> StreamResult:
        async def gen() -> AsyncIterator[bytes]:
            for part in parts:
                yield part

        return StreamResult(200, "text/event-stream", {}, iterator=gen())

    return fake


# ── StreamRestorer ───────────────────────────────────────────────────────


def test_stream_restorer_holds_split_placeholders() -> None:
    r = StreamRestorer({PH: EMAIL})
    pieces = ["mail ", "⟨", "EMAIL", "_1", "⟩", " now"]
    assert "".join(r.feed(p) for p in pieces) + r.flush() == f"mail {EMAIL} now"


def test_stream_restorer_releases_lone_brackets_and_escapes() -> None:
    r = StreamRestorer({PH: 'a"b'}, escape=lambda s: json.dumps(s)[1:-1])
    out = r.feed("3 ⟨ 4 and ⟨EMAIL_1⟩") + r.flush()
    assert out == '3 ⟨ 4 and a\\"b'  # inner placeholder found despite the stray ⟨
    held = StreamRestorer({PH: EMAIL})
    assert held.feed("dangling ⟨EMA") == "dangling "
    assert held.flush() == "⟨EMA"  # never dropped


# ── OpenAI streaming ─────────────────────────────────────────────────────


def _openai_text(body: bytes) -> str:
    text = ""
    for line in body.decode().split("\n"):
        if line.startswith("data: ") and line[6:].strip() != "[DONE]":
            event = json.loads(line[6:])  # every frame must be valid JSON
            for choice in event.get("choices", []):
                text += choice.get("delta", {}).get("content") or ""
    return text


def _openai_frames(*deltas: str, finish: bool = False) -> bytes:
    frames = [{"choices": [{"index": 0, "delta": {"content": d}}]} for d in deltas]
    if finish:
        frames.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    # Raw UTF-8 like real upstreams, so multi-byte characters can be split.
    out = b"".join(f"data: {json.dumps(f, ensure_ascii=False)}\n\n".encode() for f in frames)
    return out + b"data: [DONE]\n\n"


def _post_openai_stream(client: TestClient, *parts: bytes) -> bytes:
    req = {"model": "m", "stream": True, "messages": [{"role": "user", "content": EMAIL}]}
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        side_effect=_stream(*parts),
    ):
        with client.stream("POST", "/v1/chat/completions", json=req) as resp:
            return b"".join(resp.iter_bytes())


def test_openai_stream_restores_placeholder_split_across_deltas(client: TestClient) -> None:
    body = _post_openai_stream(client, _openai_frames("Reach ", "⟨", "EMAIL", "_1", "⟩", "."))
    assert _openai_text(body) == f"Reach {EMAIL}."


def test_openai_stream_survives_lines_split_across_network_chunks(client: TestClient) -> None:
    frames = _openai_frames("café ", PH)
    cut = frames.index("é".encode()) + 1  # mid multi-byte character, mid line
    body = _post_openai_stream(client, frames[:cut], frames[cut:])
    assert _openai_text(body) == f"café {EMAIL}"


def test_openai_stream_releases_held_text_at_finish(client: TestClient) -> None:
    body = _post_openai_stream(client, _openai_frames("x ⟨", "EMA", finish=True))
    assert _openai_text(body) == "x ⟨EMA"


# ── Anthropic streaming ──────────────────────────────────────────────────


def _anthropic_event(event: dict[str, Any]) -> bytes:
    return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()


def _delta(index: int, kind: str, value: str) -> bytes:
    field = "text" if kind == "text_delta" else "partial_json"
    return _anthropic_event(
        {"type": "content_block_delta", "index": index, "delta": {"type": kind, field: value}}
    )


def _collect_anthropic(body: bytes) -> dict[int, str]:
    """Concatenate each block's deltas; also checks every frame's framing."""
    blocks: dict[int, str] = {}
    for frame in body.decode().split("\n\n"):
        if not frame.strip():
            continue
        lines = frame.split("\n")
        assert lines[0].startswith("event: ") and lines[1].startswith("data: "), frame
        event = json.loads(lines[1][6:])
        assert lines[0][7:] == event["type"]
        if event["type"] == "content_block_delta":
            delta = event["delta"]
            blocks.setdefault(event["index"], "")
            blocks[event["index"]] += delta.get("text", delta.get("partial_json", ""))
    return blocks


def _post_anthropic_stream(client: TestClient, *parts: bytes) -> bytes:
    req = {
        "model": "m",
        "max_tokens": 50,
        "stream": True,
        "messages": [{"role": "user", "content": f"mail {EMAIL} about {'a"b'}"}],
    }
    with patch(
        "llm_redactor.transport.http_proxy.forward_anthropic_messages_stream",
        side_effect=_stream(*parts),
    ):
        with client.stream("POST", "/v1/messages", json=req) as resp:
            assert resp.status_code == 200
            return b"".join(resp.iter_bytes())


def test_anthropic_stream_restores_text_and_tool_call_deltas(client: TestClient) -> None:
    body = _post_anthropic_stream(
        client,
        _delta(0, "text_delta", "Mailing ⟨EMA"),
        _delta(0, "text_delta", "IL_1⟩ now"),
        _anthropic_event({"type": "content_block_stop", "index": 0}),
        _delta(1, "input_json_delta", '{"to": "⟨EMAIL'),
        _delta(1, "input_json_delta", '_1⟩"}'),
        _anthropic_event({"type": "content_block_stop", "index": 1}),
    )
    blocks = _collect_anthropic(body)
    assert blocks[0] == f"Mailing {EMAIL} now"
    assert json.loads(blocks[1]) == {"to": EMAIL}


def test_anthropic_tool_call_originals_are_json_escaped() -> None:
    restorer = SSETextRestorer({PH: 'say "hi"\n'})
    out = restorer.feed_chunk(_delta(0, "input_json_delta", '{"msg": "⟨EMAIL_1⟩"}')).decode()
    partial = json.loads(out.split("data: ", 1)[1])["delta"]["partial_json"]
    assert json.loads(partial) == {"msg": 'say "hi"\n'}


def test_anthropic_held_text_is_released_inside_its_own_block() -> None:
    restorer = SSETextRestorer({PH: EMAIL})
    out = (
        restorer.feed_chunk(
            _delta(0, "text_delta", "ends with ⟨EMA")
            + _anthropic_event({"type": "content_block_stop", "index": 0})
            + _delta(1, "text_delta", "next block")
        )
        + restorer.flush()
    )
    blocks = _collect_anthropic(out)
    assert blocks == {0: "ends with ⟨EMA", 1: "next block"}
    text = out.decode()
    assert text.index("⟨EMA") < text.index("content_block_stop")


# ── Anthropic request scope ──────────────────────────────────────────────


def _post_messages(client: TestClient, body: dict[str, Any], reply: list[Any]) -> tuple:
    sent: dict[str, Any] = {}

    async def fake(outgoing: dict[str, Any], *_a: Any, **_k: Any) -> dict[str, Any]:
        sent.update(outgoing)
        return {"content": reply}

    with patch("llm_redactor.transport.http_proxy.forward_anthropic_messages", side_effect=fake):
        resp = client.post("/v1/messages", json={"model": "m", "max_tokens": 5, **body})
    return sent, resp


def test_anthropic_redacts_system_tool_results_tool_inputs_and_documents(
    client: TestClient,
) -> None:
    body = {
        "system": [{"type": "text", "text": f"Operator: {EMAIL}"}],
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "bash",
                     "input": {"command": f"export K={AWS}", "args": [EMAIL]}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": f"AWS_KEY={AWS}"},
                    {"type": "tool_result", "tool_use_id": "t2",
                     "content": [{"type": "text", "text": f"owner {EMAIL}"}]},
                    {"type": "document", "source": {"type": "text", "media_type": "text/plain",
                                                    "data": f"contact {EMAIL}"}},
                ],
            },
        ],
    }  # fmt: skip
    sent, _ = _post_messages(client, body, [{"type": "text", "text": "ok"}])
    forwarded = json.dumps(sent)
    assert EMAIL not in forwarded and AWS not in forwarded
    assert sent["messages"][0]["content"][0]["input"]["args"] == [PH]


def test_anthropic_restores_tool_use_inputs_in_responses(client: TestClient) -> None:
    reply = [
        {"type": "text", "text": f"Writing {PH}"},
        {"type": "tool_use", "id": "t9", "name": "write", "input": {"body": f"to: {PH}"}},
    ]
    _, resp = _post_messages(client, {"messages": [{"role": "user", "content": EMAIL}]}, reply)
    content = resp.json()["content"]
    assert content[0]["text"] == f"Writing {EMAIL}"
    assert content[1]["input"] == {"body": f"to: {EMAIL}"}


async def test_signed_requests_get_the_same_scope() -> None:
    raw = json.dumps(
        {
            "model": "m",
            "system": f"ops {EMAIL}",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": f"recall {EMAIL}", "signature": "c2ln"},
                        {"type": "tool_use", "id": "t1", "name": "b", "input": {"c": AWS}},
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "t1", "content": AWS}],
                },
            ],
        }
    ).encode()

    async def detect(text: str) -> list:
        return detect_all(text, use_ner=False)

    result = await redact_signed_request(raw, detect, PlaceholderGenerator())
    new = result.new_raw.decode()
    assert AWS not in new
    assert new.count(EMAIL) == 1 and f'"thinking": "recall {EMAIL}"' in new  # signed: untouched


# ── count_tokens, content parts, errors, passthrough marking ────────────


def test_count_tokens_is_redacted_like_messages(httpx_mock: Any, client: TestClient) -> None:
    httpx_mock.add_response(url="https://api.openai.com/v1/messages/count_tokens", json={"n": 1})
    body = {"model": "m", "system": EMAIL, "messages": [{"role": "user", "content": AWS}]}
    resp = client.post("/v1/messages/count_tokens", json=body)
    sent = httpx_mock.get_request()
    assert resp.status_code == 200 and resp.headers["x-llm-redactor-mode"] == "redacted"
    assert sent is not None
    assert EMAIL.encode() not in sent.content and AWS.encode() not in sent.content


def test_count_tokens_rejects_invalid_json_locally(client: TestClient) -> None:
    resp = client.post("/v1/messages/count_tokens", content=b"{not json")
    assert resp.status_code == 400


def test_openai_content_parts_are_redacted(client: TestClient) -> None:
    sent: dict[str, Any] = {}

    async def fake(outgoing: dict[str, Any], *_a: Any, **_k: Any) -> dict[str, Any]:
        sent.update(outgoing)
        return {"choices": [{"index": 0, "message": {"role": "assistant", "content": PH}}]}

    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
    parts = [{"type": "text", "text": f"mail {EMAIL}"}, image]
    with patch("llm_redactor.pipeline.option_b.forward_chat_completion", side_effect=fake):
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "m", "messages": [{"role": "user", "content": parts}]},
        )
    assert EMAIL not in json.dumps(sent)
    assert sent["messages"][0]["content"][1] == image
    assert resp.json()["choices"][0]["message"]["content"] == EMAIL
    assert resp.json()["redactor"]["leak_audit"]["original_span_text_survived"] == 0


def test_openai_upstream_status_passes_through(httpx_mock: Any, client: TestClient) -> None:
    httpx_mock.add_response(
        url="https://api.openai.com/v1/chat/completions",
        status_code=429,
        json={"error": {"type": "rate_limited"}},
        headers={"retry-after": "7"},
    )
    resp = client.post(
        "/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert resp.status_code == 429  # was a bare 500
    assert resp.headers["retry-after"] == "7"


def test_openai_stream_connect_failure_is_typed(httpx_mock: Any, client: TestClient) -> None:
    for _ in range(3):  # one attempt + the bounded retries
        httpx_mock.add_exception(httpx.ConnectError(""))
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "m", "stream": True, "messages": [{"role": "user", "content": "x"}]},
    )
    assert resp.status_code == 502 and resp.json()["error"]["message"] == "ConnectError"


def test_catch_all_marks_raw_passthrough(httpx_mock: Any, client: TestClient) -> None:
    httpx_mock.add_response(url="https://api.openai.com/v1/models", json={"data": []})
    resp = client.get("/v1/models")
    assert resp.headers["x-llm-redactor-mode"] == "raw-passthrough"
