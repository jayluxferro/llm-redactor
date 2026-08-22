"""Tests for the object-index + field-insertion surgery API."""

import json

from llm_redactor.redact.raw_surgery import (
    InsertOp,
    SurgeryError,
    index_objects,
    insert_fields,
)


def _body() -> bytes:
    return json.dumps(
        {
            "system": [{"type": "text", "text": "x" * 4200}],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "thinking", "thinking": "s", "signature": "sig"},
                        {"type": "text", "text": "hi"},
                        {"type": "tool_result", "tool_use_id": "t1", "content": "r"},
                    ],
                }
            ],
        }
    ).encode()


def test_index_objects_reports_blocks_and_protection() -> None:
    objs = index_objects(_body())
    by_path = {o.path: o for o in objs}
    assert by_path[("system", 0)].block_type == "text"
    assert not by_path[("system", 0)].protected
    thinking = by_path[("messages", 0, "content", 0)]
    assert thinking.block_type == "thinking"
    assert thinking.protected
    text = by_path[("messages", 0, "content", 1)]
    assert text.block_type == "text"
    assert not text.protected
    tool_result = by_path[("messages", 0, "content", 2)]
    assert tool_result.block_type == "tool_result"


def test_insert_fields_tags_targets_and_preserves_signed_bytes() -> None:
    raw = _body()
    signature_needle = b'"signature": "sig"'
    objs = index_objects(raw)
    targets = [
        o.brace_open
        for o in objs
        if o.path == ("system", 0)
        or (
            len(o.path) == 4
            and o.path[0] == "messages"
            and o.path[2] == "content"
            and o.block_type in ("text", "tool_result")
            and not o.protected
        )
    ]
    assert len(targets) == 3
    out = insert_fields(
        raw,
        [InsertOp(brace_open=b, field=b'"cache_control":{"type":"ephemeral"}') for b in targets],
    )
    doc = json.loads(out)
    assert "cache_control" in doc["system"][0]
    assert "cache_control" in doc["messages"][0]["content"][1]
    assert "cache_control" in doc["messages"][0]["content"][2]
    assert "cache_control" not in doc["messages"][0]["content"][0]
    assert signature_needle in out


def test_insert_fields_handles_empty_objects() -> None:
    raw = b'{"a": {}, "b": {}}'
    objs = index_objects(raw)
    opens = [o.brace_open for o in objs if o.path in (("a",), ("b",))]
    out = insert_fields(raw, [InsertOp(brace_open=o, field=b'"x":1') for o in opens])
    assert json.loads(out) == {"a": {"x": 1}, "b": {"x": 1}}


def test_insert_fields_rejects_duplicate_and_invalid_targets() -> None:
    import pytest

    raw = b'{"a": {"k": 1}}'
    brace = index_objects(raw)[0].brace_open
    with pytest.raises(SurgeryError):
        insert_fields(
            raw,
            [
                InsertOp(brace_open=brace, field=b'"x":1'),
                InsertOp(brace_open=brace, field=b'"y":2'),
            ],
        )
    with pytest.raises(SurgeryError):
        insert_fields(raw, [InsertOp(brace_open=1, field=b'"x":1')])  # offset 1 is '"', not a brace
