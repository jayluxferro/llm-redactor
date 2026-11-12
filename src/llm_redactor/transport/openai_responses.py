"""Redaction and restoration for the OpenAI Responses API (``/v1/responses``).

The Responses API (used by Codex and other newer OpenAI agents) has its own
shapes, so it gets its own helpers instead of riding on the chat path:

request   ``instructions`` and ``input`` (a string, or items: messages with
          ``input_text`` / ``output_text`` parts, ``function_call`` arguments,
          ``function_call_output`` output, custom-tool input/output, local
          shell commands, and replayed reasoning summaries / text; never
          ``encrypted_content``)
response  ``output`` items (message text, function-call arguments, custom-tool
          input, local shell commands, reasoning summaries)

Whatever is restored on the way back must be redacted on the way out:
clients replay earlier output items (Codex sends its reasoning items and
shell calls every turn), so an item kind restored here but not redacted
there carries the restored values upstream in the clear.
stream    typed SSE events: ``*.delta`` events carry fragments, ``*.done``,
          ``output_item.*``, ``content_part.*`` and ``response.completed``
          carry whole values

Until this module existed, ``/v1/responses`` hit the raw catch-all and went
upstream unredacted.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..redact.restore import StreamRestorer, json_fragment, restore, restore_in_json_text

if TYPE_CHECKING:
    from ..pipeline.option_b import RequestScrubber

_TOOL_OUTPUT_ITEMS = frozenset(
    {"function_call_output", "custom_tool_call_output", "local_shell_call_output"}
)


async def redact_responses_body(body: dict[str, Any], scrub: RequestScrubber) -> dict[str, Any]:
    """Redact every model-visible string of a Responses request."""
    out = dict(body)
    if isinstance(body.get("instructions"), str):
        out["instructions"] = await scrub.text(body["instructions"])
    value = body.get("input")
    if isinstance(value, str):
        out["input"] = await scrub.text(value)
    elif isinstance(value, list):
        out["input"] = [await _redact_item(item, scrub) for item in value]
    return out


async def _redact_item(item: Any, scrub: RequestScrubber) -> Any:
    if not isinstance(item, dict):
        return item
    kind = item.get("type", "message" if "role" in item else None)
    if kind == "message":
        content = item.get("content")
        if isinstance(content, str):
            return {**item, "content": await scrub.text(content)}
        if isinstance(content, list):
            return {**item, "content": [await scrub.part(p) for p in content]}
        return item
    if kind == "function_call" and isinstance(item.get("arguments"), str):
        return {**item, "arguments": await scrub.json_text(item["arguments"])}
    if kind == "custom_tool_call" and isinstance(item.get("input"), str):
        return {**item, "input": await scrub.text(item["input"], tool_content=True)}
    if kind in _TOOL_OUTPUT_ITEMS:
        output = item.get("output")
        if isinstance(output, str):
            return {**item, "output": await scrub.text(output, tool_content=True)}
        if isinstance(output, list):
            parts = [await scrub.part(p, tool_content=True) for p in output]
            return {**item, "output": parts}
    if kind == "reasoning":
        # Summary and reasoning text only: encrypted_content is ciphertext the
        # server must get back byte for byte.
        out = dict(item)
        for field in ("summary", "content"):
            if isinstance(item.get(field), list):
                out[field] = [await scrub.part(p) for p in item[field]]
        return out
    if kind == "local_shell_call" and isinstance(item.get("action"), dict):
        return {**item, "action": await _redact_shell_action(item["action"], scrub)}
    return item


async def _redact_shell_action(action: dict[str, Any], scrub: RequestScrubber) -> dict[str, Any]:
    out = dict(action)
    if isinstance(action.get("command"), list):
        out["command"] = [
            await scrub.text(c, tool_content=True) if isinstance(c, str) else c
            for c in action["command"]
        ]
    if isinstance(action.get("env"), dict):
        out["env"] = {
            k: await scrub.text(v, tool_content=True) if isinstance(v, str) else v
            for k, v in action["env"].items()
        }
    return out


def restore_responses(response: dict[str, Any], reverse_map: dict[str, str]) -> None:
    """Restore placeholders in a Responses response object, in place."""
    for item in response.get("output") or []:
        restore_item(item, reverse_map)
    if isinstance(response.get("output_text"), str):
        response["output_text"] = restore(response["output_text"], reverse_map)


def restore_item(item: Any, reverse_map: dict[str, str]) -> None:
    if not isinstance(item, dict):
        return
    kind = item.get("type")
    if kind == "message":
        for part in item.get("content") or []:
            _restore_part(part, reverse_map)
    elif kind == "function_call" and isinstance(item.get("arguments"), str):
        item["arguments"] = restore_in_json_text(item["arguments"], reverse_map)
    elif kind == "custom_tool_call" and isinstance(item.get("input"), str):
        item["input"] = restore(item["input"], reverse_map)
    elif kind == "reasoning":
        for part in item.get("summary") or []:
            _restore_part(part, reverse_map)
    elif kind == "local_shell_call" and isinstance(item.get("action"), dict):
        action = item["action"]
        if isinstance(action.get("command"), list):
            action["command"] = [
                restore(c, reverse_map) if isinstance(c, str) else c for c in action["command"]
            ]


def _restore_part(part: Any, reverse_map: dict[str, str]) -> None:
    if isinstance(part, dict) and isinstance(part.get("text"), str):
        part["text"] = restore(part["text"], reverse_map)


# Fragment events: (event type, the field carrying the fragment, JSON text?).
# The matching ".done" event (type without ".delta") carries the whole value
# in the field named by _DONE_FIELDS.
_DELTA_EVENTS: dict[str, bool] = {
    "response.output_text.delta": False,
    "response.refusal.delta": False,
    "response.reasoning_summary_text.delta": False,
    "response.function_call_arguments.delta": True,
    "response.custom_tool_call_input.delta": False,
}
_DONE_FIELDS: dict[str, str] = {
    "response.output_text.done": "text",
    "response.refusal.done": "refusal",
    "response.reasoning_summary_text.done": "text",
    "response.function_call_arguments.done": "arguments",
    "response.custom_tool_call_input.done": "input",
}
_KEY_FIELDS = ("output_index", "content_index", "summary_index")


def _stream_key(event: dict[str, Any], kind: str) -> tuple[Any, ...]:
    return (kind, *(event.get(f) for f in _KEY_FIELDS))


class ResponsesSSERestorer:
    """Restore placeholders in a Responses SSE stream.

    Each fragment stream (one per output item / content part) holds back an
    incomplete placeholder; whatever is still held when its ``.done`` event
    arrives is emitted first as one synthetic delta, so a client that
    concatenates deltas never loses characters.  ``event:`` lines are held
    until their ``data:`` line so a synthetic frame never splits a frame.
    """

    def __init__(self, reverse_map: dict[str, str]) -> None:
        self._map = reverse_map
        self._line = bytearray()
        self._pending_event: bytes | None = None
        self._streams: dict[tuple[Any, ...], tuple[dict[str, Any], StreamRestorer]] = {}

    def feed_chunk(self, chunk: bytes) -> bytes:
        self._line += chunk
        out = bytearray()
        while (nl := self._line.find(b"\n")) != -1:
            line = bytes(self._line[: nl + 1])
            del self._line[: nl + 1]
            out += self._process_line(line)
        return bytes(out)

    def flush(self) -> bytes:
        rest = bytes(self._line)
        self._line.clear()
        out = self._process_line(rest) if rest else b""
        for key in list(self._streams):
            out += self._release(key)
        if self._pending_event is not None:
            out += self._pending_event
            self._pending_event = None
        return out

    def _release(self, key: tuple[Any, ...]) -> bytes:
        template, restorer = self._streams.pop(key)
        held = restorer.flush()
        if not held:
            return b""
        event = {k: v for k, v in template.items() if k != "sequence_number"}
        event["delta"] = held
        payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
        return b"event: " + str(event["type"]).encode() + b"\ndata: " + payload + b"\n\n"

    def _process_line(self, line: bytes) -> bytes:
        if line.startswith(b"event:"):
            previous, self._pending_event = self._pending_event or b"", line
            return previous
        pending, self._pending_event = self._pending_event or b"", None
        if not line.startswith(b"data:"):
            return pending + line
        try:
            event = json.loads(line[5:].strip())
        except ValueError:
            return pending + line
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            return pending + line
        prefix, changed = self._rewrite(event)
        if not changed:
            return prefix + pending + line
        tail = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
        return prefix + pending + b"data: " + payload + tail

    def _rewrite(self, event: dict[str, Any]) -> tuple[bytes, bool]:
        """Restore one event in place; returns (frames to emit before it, changed)."""
        kind = event["type"]
        if kind in _DELTA_EVENTS and isinstance(event.get("delta"), str):
            key = _stream_key(event, kind)
            if key not in self._streams:
                escape = json_fragment if _DELTA_EVENTS[kind] else None
                self._streams[key] = (dict(event), StreamRestorer(self._map, escape=escape))
            new = self._streams[key][1].feed(event["delta"])
            changed = new != event["delta"]
            event["delta"] = new
            return b"", changed
        if kind in _DONE_FIELDS:
            delta_kind = kind.removesuffix(".done") + ".delta"
            key = _stream_key(event, delta_kind)
            prefix = self._release(key) if key in self._streams else b""
            field = _DONE_FIELDS[kind]
            value = event.get(field)
            if isinstance(value, str):
                json_text = _DELTA_EVENTS[delta_kind]
                restored = (
                    restore_in_json_text(value, self._map)
                    if json_text
                    else restore(value, self._map)
                )
                event[field] = restored
                return prefix, restored != value
            return prefix, False
        before = json.dumps(event, sort_keys=True)
        if kind in ("response.output_item.added", "response.output_item.done"):
            restore_item(event.get("item"), self._map)
        elif kind in ("response.content_part.added", "response.content_part.done"):
            _restore_part(event.get("part"), self._map)
        elif isinstance(event.get("response"), dict):  # created / completed / incomplete / ...
            restore_responses(event["response"], self._map)
        else:
            return b"", False
        return b"", json.dumps(event, sort_keys=True) != before
