"""Tool-bearing chat requests, the Responses / completions / embeddings routes,
the unknown-path policy and signed-body refusal.  Upstreams are stubbed."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.redact.raw_surgery import SurgeryError
from llm_redactor.transport.cloud import StreamResult
from llm_redactor.transport.http_proxy import app, configure

EMAIL = "bob@corp.example"
AWS = "AKIAIOSFODNN7EXAMPLE"
PH = "⟨EMAIL_1⟩"
TRICKY = 'he said "hi"\n'  # an original that must be JSON-escaped in arguments


def _client(**transport: Any) -> TestClient:
    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    for key, value in transport.items():
        setattr(cfg.transport, key, value)
    configure(cfg, use_ner=False)
    return TestClient(app)


def _stream(*parts: bytes):
    async def fake(*_a: Any, **_k: Any) -> StreamResult:
        async def gen() -> AsyncIterator[bytes]:
            for part in parts:
                yield part

        return StreamResult(200, "text/event-stream", {}, iterator=gen())

    return fake


def _capture(reply: dict[str, Any]):
    sent: dict[str, Any] = {}

    async def fake(*args: Any, **_k: Any) -> dict[str, Any]:
        body = next(a for a in args if isinstance(a, dict))
        sent.update(body)
        return json.loads(json.dumps(reply))

    return sent, fake


# ── OpenAI chat with tools ───────────────────────────────────────────────

TOOLS = [{"type": "function", "function": {"name": "send", "parameters": {"type": "object"}}}]
CHAT_WITH_TOOLS = {
    "model": "m",
    "tools": TOOLS,
    "messages": [
        {"role": "user", "content": f"mail {EMAIL}"},
        {
            "role": "assistant",
            "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "send", "arguments": json.dumps({"key": AWS})}},
            ],
        },
        {"role": "tool", "tool_call_id": "c1", "content": f"AWS_KEY={AWS}"},
    ],
}  # fmt: skip


def test_tool_bearing_chat_requests_are_redacted_by_default() -> None:
    reply = {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"id": "c2", "type": "function",
                         "function": {"name": "send", "arguments": json.dumps({"to": PH})}},
                    ],
                },
            }
        ]
    }  # fmt: skip
    sent, fake = _capture(reply)
    with patch("llm_redactor.pipeline.option_b.forward_chat_completion", side_effect=fake):
        resp = _client().post("/v1/chat/completions", json=CHAT_WITH_TOOLS)
    forwarded = json.dumps(sent)
    assert EMAIL not in forwarded and AWS not in forwarded
    assert sent["tools"] == TOOLS  # schemas untouched
    call = resp.json()["choices"][0]["message"]["tool_calls"][0]
    assert json.loads(call["function"]["arguments"]) == {"to": EMAIL}


def test_tool_call_arguments_restore_with_json_escaping() -> None:
    from llm_redactor.pipeline.option_b import restore_openai_message

    message = {"tool_calls": [{"function": {"arguments": json.dumps({"note": PH})}}]}
    restore_openai_message(message, {PH: TRICKY})
    assert json.loads(message["tool_calls"][0]["function"]["arguments"]) == {"note": TRICKY}


def test_streamed_tool_call_arguments_are_restored() -> None:
    def chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
        event = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
        return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode()

    def args(fragment: str) -> dict[str, Any]:
        return {"tool_calls": [{"index": 0, "function": {"arguments": fragment}}]}

    parts = [
        chunk(args('{"to": "⟨EMA')),
        chunk(args('IL_1⟩"}')),
        chunk({}, finish="tool_calls"),
        b"data: [DONE]\n\n",
    ]
    body = {**CHAT_WITH_TOOLS, "stream": True}
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        side_effect=_stream(*parts),
    ):
        with _client().stream("POST", "/v1/chat/completions", json=body) as resp:
            raw = b"".join(resp.iter_bytes()).decode()
    fragments = ""
    for line in raw.split("\n"):
        if line.startswith("data: {"):
            for choice in json.loads(line[6:])["choices"]:
                for tc in choice.get("delta", {}).get("tool_calls", []):
                    fragments += tc["function"].get("arguments", "")
    assert json.loads(fragments) == {"to": EMAIL}


def test_tools_policy_bypass_and_refuse_still_exist() -> None:
    sent, fake = _capture({"choices": []})
    with patch("llm_redactor.transport.cloud.forward_chat_completion", side_effect=fake):
        resp = _client(tools_policy="bypass").post("/v1/chat/completions", json=CHAT_WITH_TOOLS)
    assert resp.headers["x-llm-redactor-mode"] == "bypass-tools" and EMAIL in json.dumps(sent)
    resp = _client(tools_policy="refuse").post("/v1/chat/completions", json=CHAT_WITH_TOOLS)
    assert resp.status_code == 422


# ── signed bodies ────────────────────────────────────────────────────────


def test_unredactable_signed_body_is_refused_not_forwarded() -> None:
    body = {
        "model": "m",
        "max_tokens": 5,
        "messages": [
            {
                "role": "assistant",
                "content": [{"type": "thinking", "thinking": "x", "signature": "s"}],
            },
            {"role": "user", "content": f"mail {EMAIL}"},
        ],
    }
    with (
        patch(
            "llm_redactor.transport.http_proxy.redact_signed_request",
            side_effect=SurgeryError("boom"),
        ),
        patch("llm_redactor.transport.http_proxy.forward_anthropic_raw") as forward,
    ):
        resp = _client().post("/v1/messages", json=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["reason"] == "signed_body_unredactable"
    forward.assert_not_called()


async def test_tool_results_are_scrubbed_as_tool_content() -> None:
    from llm_redactor.pipeline.option_b import OptionBPipeline
    from llm_redactor.transport.http_proxy import _redact_anthropic_body

    flags: list[bool] = []

    async def record(self: Any, text: str, *, tool_content: bool = False) -> list:
        flags.append(tool_content)
        return []

    pipeline = OptionBPipeline(config=Config(), use_ner=False)
    body = {
        "system": "sys",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "hi"},
                {"type": "tool_result", "tool_use_id": "t", "content": "out"},
            ]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t", "name": "n", "input": {"cmd": "ls"}},
            ]},
        ],
    }  # fmt: skip
    with patch.object(OptionBPipeline, "detect_spans", record):
        await _redact_anthropic_body(body, pipeline.scrubber(None))
    assert flags == [False, False, True, True]  # system, text, tool_result, tool_use


# ── Responses API ────────────────────────────────────────────────────────


def test_responses_request_redaction_and_response_restore() -> None:
    body = {
        "model": "m",
        "instructions": f"operator {EMAIL}",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": f"key {AWS}"}]},
            {"type": "function_call", "call_id": "c", "name": "f",
             "arguments": json.dumps({"k": AWS})},
            {"type": "function_call_output", "call_id": "c", "output": f"AWS={AWS}"},
        ],
    }  # fmt: skip
    reply = {
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": f"to {PH}"}]},
            {"type": "function_call", "arguments": json.dumps({"to": PH})},
        ]
    }
    sent, fake = _capture(reply)
    with patch("llm_redactor.transport.http_proxy.forward_openai_json", side_effect=fake):
        resp = _client().post("/v1/responses", json=body)
    assert EMAIL not in json.dumps(sent) and AWS not in json.dumps(sent)
    output = resp.json()["output"]
    assert output[0]["content"][0]["text"] == f"to {EMAIL}"
    assert json.loads(output[1]["arguments"]) == {"to": EMAIL}


def test_replayed_reasoning_and_shell_items_are_redacted_and_restored() -> None:
    # Codex replays its reasoning items (store=false) and shell calls every
    # turn.  The proxy restores real values into reasoning summaries on the
    # way back, so a replayed summary carried them upstream in the clear.
    fernet = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
    body = {
        "model": "m",
        "input": [
            {"type": "reasoning", "id": "rs_1", "encrypted_content": fernet,
             "summary": [{"type": "summary_text", "text": f"mail {EMAIL}"}],
             "content": [{"type": "reasoning_text", "text": f"key {AWS}"}]},
            {"type": "local_shell_call", "call_id": "s1", "status": "completed",
             "action": {"type": "exec", "command": ["bash", "-lc", f"echo {AWS}"],
                        "env": {"TOKEN": AWS}}},
        ],
    }  # fmt: skip
    reply = {
        "output": [
            {"type": "local_shell_call", "call_id": "s2",
             "action": {"type": "exec", "command": ["bash", "-lc", f"mail {PH}"]}},
        ]
    }  # fmt: skip
    sent, fake = _capture(reply)
    with patch("llm_redactor.transport.http_proxy.forward_openai_json", side_effect=fake):
        resp = _client().post("/v1/responses", json=body)
    assert EMAIL not in json.dumps(sent) and AWS not in json.dumps(sent)
    reasoning = sent["input"][0]
    assert reasoning["encrypted_content"] == fernet and reasoning["id"] == "rs_1"
    assert reasoning["summary"][0]["type"] == "summary_text"
    assert sent["input"][1]["action"]["command"][:2] == ["bash", "-lc"]
    assert resp.json()["output"][0]["action"]["command"] == ["bash", "-lc", f"mail {EMAIL}"]


def _responses_event(event: dict[str, Any]) -> bytes:
    return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()


def test_responses_stream_restores_split_placeholders_and_done_events() -> None:
    def delta(text: str) -> dict[str, Any]:
        return {"type": "response.output_text.delta", "item_id": "m1", "output_index": 0,
                "content_index": 0, "delta": text}  # fmt: skip

    parts = [
        _responses_event(delta("mail ⟨EMA")),
        _responses_event(delta("IL_1⟩ and ⟨EM")),  # the second one never completes
        _responses_event({"type": "response.output_text.done", "item_id": "m1",
                          "output_index": 0, "content_index": 0,
                          "text": f"mail {PH} and ⟨EM"}),
        _responses_event({"type": "response.completed", "response": {"output": [
            {"type": "message", "content": [{"type": "output_text", "text": f"mail {PH}"}]}]}}),
    ]  # fmt: skip
    body = {"model": "m", "stream": True, "input": f"mail {EMAIL}"}
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        side_effect=_stream(*parts),
    ):
        with _client().stream("POST", "/v1/responses", json=body) as resp:
            raw = b"".join(resp.iter_bytes()).decode()
    deltas, done, completed = "", None, None
    for frame in raw.split("\n\n"):
        if not frame.strip():
            continue
        event_line, data_line = frame.split("\n")[:2]
        event = json.loads(data_line[6:])
        assert event_line == f"event: {event['type']}"  # framing intact
        if event["type"] == "response.output_text.delta":
            deltas += event["delta"]
        elif event["type"] == "response.output_text.done":
            done = event["text"]
        elif event["type"] == "response.completed":
            completed = event["response"]["output"][0]["content"][0]["text"]
    assert deltas == f"mail {EMAIL} and ⟨EM"  # held tail released before .done
    assert done == f"mail {EMAIL} and ⟨EM" and completed == f"mail {EMAIL}"


# ── completions, embeddings ──────────────────────────────────────────────


def test_completions_prompt_redacted_and_text_restored() -> None:
    sent, fake = _capture({"choices": [{"index": 0, "text": f"hello {PH}"}]})
    with patch("llm_redactor.transport.http_proxy.forward_openai_json", side_effect=fake):
        resp = _client().post("/v1/completions", json={"model": "m", "prompt": f"to {EMAIL}"})
    assert EMAIL not in json.dumps(sent)
    assert resp.json()["choices"][0]["text"] == f"hello {EMAIL}"


def test_completions_stream_text_is_restored() -> None:
    def chunk(text: str, finish: str | None = None) -> bytes:
        event = {"choices": [{"index": 0, "text": text, "finish_reason": finish}]}
        return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode()

    parts = [chunk("hi ⟨EMAIL"), chunk("_1⟩ bye", finish="stop"), b"data: [DONE]\n\n"]
    body = {"model": "m", "stream": True, "prompt": f"to {EMAIL}"}
    with patch(
        "llm_redactor.transport.http_proxy.forward_chat_completion_stream",
        side_effect=_stream(*parts),
    ):
        with _client().stream("POST", "/v1/completions", json=body) as resp:
            raw = b"".join(resp.iter_bytes()).decode()
    text = "".join(
        json.loads(line[6:])["choices"][0]["text"]
        for line in raw.split("\n")
        if line.startswith("data: {")
    )
    assert text == f"hi {EMAIL} bye"


def test_embeddings_input_is_redacted() -> None:
    sent, fake = _capture({"data": [{"embedding": [0.1]}]})
    with patch("llm_redactor.transport.http_proxy.forward_openai_json", side_effect=fake):
        resp = _client().post("/v1/embeddings", json={"model": "e", "input": [EMAIL, "plain"]})
    assert sent["input"][0] == PH and sent["input"][1] == "plain"
    assert resp.json() == {"data": [{"embedding": [0.1]}]}


# ── unknown paths ────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/v1/messages/batches", "/v1/files", "/chat/completions"])
def test_unknown_paths_with_a_body_are_refused(path: str) -> None:
    resp = _client().post(path, json={"messages": [{"role": "user", "content": EMAIL}]})
    assert resp.status_code == 422 and resp.json()["error"]["reason"] == "unknown_path"
    if path == "/chat/completions":
        assert "missing its /v1" in resp.json()["error"]["message"]


def test_unknown_path_policy_forward(httpx_mock: Any) -> None:
    httpx_mock.add_response(url="https://api.openai.com/v1/messages/batches", json={"id": "b"})
    resp = _client(unknown_path_policy="forward").post(
        "/v1/messages/batches", json={"requests": []}
    )
    assert resp.status_code == 200 and resp.headers["x-llm-redactor-mode"] == "raw-passthrough"
