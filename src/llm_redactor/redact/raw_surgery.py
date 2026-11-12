"""Byte-preserving surgical redaction for signed Anthropic bodies.

Anthropic cryptographically signs ``thinking`` / ``redacted_thinking`` blocks
against the exact JSON bytes it served, so any ``json.loads`` / ``json.dumps``
round-trip invalidates them (the API rejects the next turn with a 400).
This module redacts sensitive spans from the *other* string values by editing
the raw bytes directly, leaving signed regions byte-identical.  The same
machinery restores placeholders in raw responses without touching signed
content there either.

Scope rules mirror the non-signed Anthropic path in ``transport/http_proxy``
(``_redact_anthropic_body``): ``system`` text, ``messages[*].content`` strings,
``text`` blocks, ``tool_result`` content (string or text blocks), every
string inside a ``tool_use`` input, and text ``document`` sources.
``thinking`` / ``redacted_thinking`` blocks and ``signature`` fields are never
modified.  Placeholders that leak into signed thinking content are
deliberately left in place — mutating them would break the signature on the
client's next turn.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..detect.types import Span
from ..observability import log_event
from .placeholder import PREFIX as PH_PREFIX
from .placeholder import SUFFIX as PH_SUFFIX
from .restore import MAX_PLACEHOLDER_LEN, StreamRestorer

__all__ = ["MAX_PLACEHOLDER_LEN"]  # re-exported: older callers import it from here

PROTECTED_BLOCK_TYPES = frozenset({"thinking", "redacted_thinking"})
PROTECTED_KEYS = frozenset({"signature"})


class SurgeryError(ValueError):
    """Raised when the raw body cannot be safely surgically edited."""


@dataclass
class StringToken:
    """One JSON string value with its raw byte extent and context."""

    path: tuple[object, ...]
    value: str
    raw_start: int  # offset of the opening quote
    raw_end: int  # offset just past the closing quote
    protected: bool = False
    block_type: str | None = None  # ``type`` of the enclosing content block


@dataclass
class ObjectRecord:
    """One JSON object with its brace extent and block context."""

    path: tuple[object, ...]
    brace_open: int  # offset of the opening '{'
    brace_close: int  # offset of the closing '}'
    block_type: str | None = None
    protected: bool = False


@dataclass
class RawRedaction:
    """Outcome of a surgical request redaction."""

    new_raw: bytes
    reverse_map: dict[str, str] = field(default_factory=dict)
    detections: list[Span] = field(default_factory=list)
    whole_token_fallbacks: int = 0


# --------------------------------------------------------------------------- #
# Raw JSON scanning
# --------------------------------------------------------------------------- #

_WS = frozenset(b" \t\r\n")
_LITERAL_STARTS = (0x74, 0x66, 0x6E, 0x2D, *range(0x30, 0x3A))  # t f n - 0-9


def _skip_ws(buf: bytes, i: int) -> int:
    while i < len(buf) and buf[i] in _WS:
        i += 1
    return i


def _scan_string(buf: bytes, i: int) -> tuple[str, int]:
    """Scan a JSON string starting at the opening quote.

    Returns ``(decoded_value, end)`` where ``end`` is just past the closing
    quote.  Decoding delegates to :func:`json.loads` so escape sequences and
    surrogate pairs match the standard exactly.
    """
    if i >= len(buf) or buf[i] != 0x22:
        raise SurgeryError(f"expected string at offset {i}")
    j = i + 1
    n = len(buf)
    while j < n:
        b = buf[j]
        if b == 0x5C:  # backslash: skip the escaped char / uXXXX
            if j + 1 >= n:
                break
            if buf[j + 1] == 0x75:  # 'u'
                j += 6
            else:
                j += 2
            continue
        if b == 0x22:
            try:
                value = json.loads(buf[i : j + 1])
            except (ValueError, UnicodeDecodeError) as exc:
                raise SurgeryError(f"undecodable string at offset {i}: {exc}") from exc
            if not isinstance(value, str):
                raise SurgeryError(f"non-string decoded at offset {i}")
            return value, j + 1
        j += 1
    raise SurgeryError(f"unterminated string at offset {i}")


def _scan_value(
    buf: bytes,
    i: int,
    path: tuple[object, ...],
    inherited_protected: bool,
    tokens: list[StringToken],
    objects: list[ObjectRecord] | None = None,
) -> int:
    """Scan one JSON value at ``i``; append string tokens. Returns end offset."""
    i = _skip_ws(buf, i)
    if i >= len(buf):
        raise SurgeryError("unexpected end of body")
    b = buf[i]
    if b == 0x22:  # string value
        value, end = _scan_string(buf, i)
        key = path[-1] if path else None
        protected = inherited_protected or (isinstance(key, str) and key in PROTECTED_KEYS)
        tokens.append(
            StringToken(path=path, value=value, raw_start=i, raw_end=end, protected=protected)
        )
        return end
    if b == 0x7B:  # '{'
        return _scan_object(buf, i, path, inherited_protected, tokens, objects)
    if b == 0x5B:  # '['
        return _scan_array(buf, i, path, inherited_protected, tokens, objects)
    if b in _LITERAL_STARTS:
        j = i
        while j < len(buf) and buf[j] not in _WS and buf[j] not in b",}]":
            j += 1
        text = buf[i:j]
        if text in (b"true", b"false", b"null") or _is_number_like(text):
            return j
        raise SurgeryError(f"unsupported literal at offset {i}: {text!r}")
    raise SurgeryError(f"unexpected byte 0x{b:02x} at offset {i}")


def _is_number_like(text: bytes) -> bool:
    body = text.lstrip(b"-")
    if not body:
        return False
    allowed = set(b"0123456789.eE+-")
    return all(ch in allowed for ch in body) and any(ch in b"0123456789" for ch in body)


def _scan_array(
    buf: bytes,
    i: int,
    path: tuple[object, ...],
    inherited_protected: bool,
    tokens: list[StringToken],
    objects: list[ObjectRecord] | None = None,
) -> int:
    i = _skip_ws(buf, i + 1)
    if i < len(buf) and buf[i] == 0x5D:
        return i + 1
    idx = 0
    while True:
        i = _scan_value(buf, i, (*path, idx), inherited_protected, tokens, objects)
        i = _skip_ws(buf, i)
        if i >= len(buf):
            raise SurgeryError("unterminated array")
        if buf[i] == 0x2C:
            idx += 1
            i += 1
            continue
        if buf[i] == 0x5D:
            return i + 1
        raise SurgeryError(f"expected ',' or ']' at offset {i}")


def _scan_object(
    buf: bytes,
    i: int,
    path: tuple[object, ...],
    inherited_protected: bool,
    tokens: list[StringToken],
    objects: list[ObjectRecord] | None = None,
) -> int:
    brace_open = i
    i = _skip_ws(buf, i + 1)
    tokens_start = len(tokens)
    block_type: str | None = None
    if i < len(buf) and buf[i] == 0x7D:
        if objects is not None:
            objects.append(ObjectRecord(path=path, brace_open=brace_open, brace_close=i))
        return i + 1
    while True:
        i = _skip_ws(buf, i)
        key, i = _scan_string(buf, i)
        i = _skip_ws(buf, i)
        if i >= len(buf) or buf[i] != 0x3A:
            raise SurgeryError(f"expected ':' at offset {i}")
        i += 1
        value_token_count = len(tokens)
        i = _scan_value(buf, i, (*path, key), inherited_protected, tokens, objects)
        if (
            key == "type"
            and len(tokens) == value_token_count + 1
            and tokens[-1].path == (*path, "type")
        ):
            block_type = tokens[-1].value
        i = _skip_ws(buf, i)
        if i >= len(buf):
            raise SurgeryError("unterminated object")
        if buf[i] == 0x2C:
            i += 1
            continue
        if buf[i] == 0x7D:
            break
        raise SurgeryError(f"expected ',' or '}}' at offset {i}")
    if block_type in PROTECTED_BLOCK_TYPES:
        for tok in tokens[tokens_start:]:
            tok.protected = True
            tok.block_type = block_type
    else:
        direct_depth = len(path) + 1
        for tok in tokens[tokens_start:]:
            if tok.block_type is None and len(tok.path) == direct_depth:
                tok.block_type = block_type
    if objects is not None:
        parent_key = path[-1] if path else None
        objects.append(
            ObjectRecord(
                path=path,
                brace_open=brace_open,
                brace_close=i,
                block_type=block_type,
                protected=(
                    inherited_protected
                    or block_type in PROTECTED_BLOCK_TYPES
                    or (isinstance(parent_key, str) and parent_key in PROTECTED_KEYS)
                ),
            )
        )
    return i + 1


def index_string_tokens(raw: bytes) -> list[StringToken]:
    """Index every JSON string value in ``raw`` with byte extents.

    Object *keys* are structure, not payload — they are not tokenized.
    Raises :class:`SurgeryError` on malformed JSON so callers can fall back to
    raw passthrough instead of corrupting the body.
    """
    tokens: list[StringToken] = []
    i = _skip_ws(raw, 0)
    end = _scan_value(raw, i, (), False, tokens)
    if _skip_ws(raw, end) != len(raw):
        raise SurgeryError("trailing bytes after top-level value")
    return tokens


def index_objects(raw: bytes) -> list[ObjectRecord]:
    """Index every JSON object in ``raw`` with brace extents and context.

    Companion to :func:`index_string_tokens`; raises :class:`SurgeryError`
    on malformed JSON.
    """
    tokens: list[StringToken] = []
    objects: list[ObjectRecord] = []
    i = _skip_ws(raw, 0)
    end = _scan_value(raw, i, (), False, tokens, objects)
    if _skip_ws(raw, end) != len(raw):
        raise SurgeryError("trailing bytes after top-level value")
    return objects


@dataclass
class InsertOp:
    """Insert a field right after a target object's opening brace."""

    brace_open: int
    field: bytes  # JSON field text without trailing comma


def insert_fields(raw: bytes, ops: list[InsertOp]) -> bytes:
    """Apply field insertions; comma handling is automatic for empty objects.

    Ops are applied right-to-left so earlier offsets stay valid; duplicate
    targets are rejected (one field per object per pass).
    """
    if not ops:
        return raw
    seen: set[int] = set()
    for op in ops:
        if op.brace_open in seen:
            raise SurgeryError(f"duplicate insert target at {op.brace_open}")
        seen.add(op.brace_open)
        if op.brace_open >= len(raw) or raw[op.brace_open] != 0x7B:
            raise SurgeryError(f"insert target {op.brace_open} is not an opening brace")
    out = raw
    for op in sorted(ops, key=lambda o: o.brace_open, reverse=True):
        j = _skip_ws(out, op.brace_open + 1)
        empty = j < len(out) and out[j] == 0x7D
        text = op.field if empty else op.field + b","
        out = out[: op.brace_open + 1] + text + out[op.brace_open + 1 :]
    return out


def _block_types(tokens: list[StringToken]) -> dict[tuple[object, ...], str]:
    """``type`` of every object, keyed by the object's path."""
    return {t.path[:-1]: t.value for t in tokens if t.path and t.path[-1] == "type"}


def _is_redactable(token: StringToken, types: dict[tuple[object, ...], str]) -> bool:
    """Mirror of the non-signed path's redaction scope (``_redact_anthropic_body``).

    Paths are matched structurally; ``types`` maps an object's path to its
    ``type`` field so a nested string can ask what block it lives in.
    """
    if token.protected or not token.value:
        return False
    p = token.path
    if p == ("system",):
        return True
    if len(p) == 3 and p[0] == "system" and p[2] == "text":
        return types.get(p[:2]) == "text"
    if len(p) < 3 or p[0] != "messages" or p[2] != "content":
        return False
    if len(p) == 3:
        return True  # messages[i].content as a plain string
    block = types.get(p[:4])
    rest = p[4:]
    if block == "text":
        return rest == ("text",)
    if block == "tool_result":
        # content as a string, or as a list of text blocks
        if rest == ("content",):
            return True
        return len(rest) == 3 and rest[::2] == ("content", "text") and types.get(p[:6]) == "text"
    if block == "tool_use":
        return bool(rest) and rest[0] == "input"  # any string inside the input
    if block == "document":
        return rest == ("source", "data") and types.get((*p[:4], "source")) == "text"
    return False


# --------------------------------------------------------------------------- #
# Decoded-offset → raw-offset mapping
# --------------------------------------------------------------------------- #


def _build_offset_map(interior: bytes, decoded_len: int) -> list[int]:
    """Map decoded character index → raw byte offset within a string interior.

    ``map[k]`` is the raw offset where decoded char ``k`` starts;
    ``len(map) == decoded_len + 1``.  Mirrors ``json.loads`` semantics for
    escapes (incl. ``\\uXXXX`` surrogate pairs) and multi-byte UTF-8.
    """
    raw_map = [0]
    i = 0
    made = 0
    n = len(interior)
    while i < n and made < decoded_len:
        b = interior[i]
        if b == 0x5C:  # escape sequence
            if interior[i + 1 : i + 2] == b"u":
                if i + 6 > n:
                    raise SurgeryError("truncated unicode escape")
                cp = int(interior[i + 2 : i + 6], 16)
                seq_len = 6
                if 0xD800 <= cp <= 0xDBFF and interior[i + 6 : i + 8] == b"\\u":
                    lo = int(interior[i + 8 : i + 12], 16)
                    if 0xDC00 <= lo <= 0xDFFF:
                        seq_len = 12  # surrogate pair decodes to one char
            else:
                seq_len = 2
        elif b < 0x80:
            seq_len = 1
        elif b >= 0xF0:
            seq_len = 4
        elif b >= 0xE0:
            seq_len = 3
        elif b >= 0xC0:
            seq_len = 2
        else:
            raise SurgeryError(f"invalid UTF-8 lead byte 0x{b:02x} at {i}")
        i += seq_len
        made += 1
        raw_map.append(i)  # offset where the next decoded char starts
    if made != decoded_len:
        raise SurgeryError(f"offset map mismatch: decoded {decoded_len}, mapped {made}")
    return raw_map


# --------------------------------------------------------------------------- #
# Replacement operations
# --------------------------------------------------------------------------- #


@dataclass
class _Op:
    start: int  # absolute raw offset
    end: int
    replacement: bytes


def _json_escape(text: str) -> bytes:
    """Encode ``text`` as the interior of a JSON string (raw UTF-8)."""
    return json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8")


def _apply_ops(raw: bytes, ops: list[_Op]) -> bytes:
    if not ops:
        return raw
    ordered = sorted(ops, key=lambda op: op.start, reverse=True)
    for k, op in enumerate(ordered):
        if op.start < 0 or op.end > len(raw) or op.start > op.end:
            raise SurgeryError(f"invalid op range [{op.start}, {op.end})")
        if k and op.end > ordered[k - 1].start:
            raise SurgeryError("overlapping replacement ops")
    out = raw
    for op in ordered:
        out = out[: op.start] + op.replacement + out[op.end :]
    return out


async def redact_signed_request(
    raw: bytes,
    detect_spans: Callable[[str], Awaitable[list[Span]]],
    gen,
) -> RawRedaction:
    """Surgically redact eligible text in a signed-block request body.

    Detection runs on decoded values; replacements are spliced into the raw
    bytes so ``thinking`` / ``redacted_thinking`` / ``signature`` regions stay
    byte-identical.  Tokens whose offsets cannot be mapped precisely (exotic
    escape sequences) fall back to whole-value replacement.
    """
    result = RawRedaction(new_raw=raw)
    tokens = index_string_tokens(raw)
    types = _block_types(tokens)
    ops: list[_Op] = []
    for tok in tokens:
        if not _is_redactable(tok, types):
            continue
        spans = await detect_spans(tok.value)
        if not spans:
            continue
        result.detections.extend(spans)
        interior = raw[tok.raw_start + 1 : tok.raw_end - 1]
        try:
            offset_map = _build_offset_map(interior, len(tok.value))
            applied_end = -1
            for span in sorted(spans, key=lambda s: s.start):
                start, end = span.start, span.end
                if start < 0 or end > len(tok.value) or start >= end:
                    continue
                if start < applied_end:  # overlaps a replaced span
                    continue
                placeholder = gen.placeholder_for(span.text, span.kind)
                result.reverse_map[placeholder] = span.text
                ops.append(
                    _Op(
                        start=tok.raw_start + 1 + offset_map[start],
                        end=tok.raw_start + 1 + offset_map[end],
                        replacement=placeholder.encode("utf-8"),
                    )
                )
                applied_end = end
        except SurgeryError:
            # Precise mapping failed — replace the entire string value.
            placeholder = gen.placeholder_for(tok.value, spans[0].kind)
            result.reverse_map[placeholder] = tok.value
            ops.append(
                _Op(
                    start=tok.raw_start,
                    end=tok.raw_end,
                    replacement=json.dumps(placeholder, ensure_ascii=False).encode("utf-8"),
                )
            )
            result.whole_token_fallbacks += 1
    result.new_raw = _apply_ops(raw, ops)
    return result


def _find_placeholders(value: str) -> list[tuple[int, int, str]]:
    """Locate ``⟨…⟩`` placeholder candidates in a decoded string."""
    out: list[tuple[int, int, str]] = []
    i = 0
    while True:
        i = value.find(PH_PREFIX, i)
        if i == -1:
            break
        j = value.find(PH_SUFFIX, i + 1)
        if j == -1:
            break
        out.append((i, j + 1, value[i : j + 1]))
        i = j + 1
    return out


def restore_response_bytes(raw: bytes, reverse_map: dict[str, str]) -> bytes:
    """Restore placeholders in a raw (non-streaming) response body.

    Signed regions (``thinking`` / ``redacted_thinking`` / ``signature``) are
    left byte-identical.  On any scan failure the body is returned unchanged —
    placeholders may reach the client, but nothing is corrupted.
    """
    if not reverse_map:
        return raw
    try:
        tokens = index_string_tokens(raw)
    except SurgeryError:
        log_event("surgery_restore_scan_failed")
        return raw
    ops: list[_Op] = []
    for tok in tokens:
        if tok.protected or PH_PREFIX not in tok.value:
            continue
        spans = _find_placeholders(tok.value)
        if not spans:
            continue
        interior = raw[tok.raw_start + 1 : tok.raw_end - 1]
        try:
            offset_map = _build_offset_map(interior, len(tok.value))
            for start, end, placeholder in spans:
                replacement = reverse_map.get(placeholder)
                if replacement is None:
                    continue
                ops.append(
                    _Op(
                        start=tok.raw_start + 1 + offset_map[start],
                        end=tok.raw_start + 1 + offset_map[end],
                        replacement=_json_escape(replacement),
                    )
                )
        except SurgeryError:
            new_value = tok.value
            for _, _, placeholder in spans:
                if placeholder in reverse_map:
                    new_value = new_value.replace(placeholder, reverse_map[placeholder])
            ops.append(
                _Op(
                    start=tok.raw_start,
                    end=tok.raw_end,
                    replacement=json.dumps(new_value, ensure_ascii=False).encode("utf-8"),
                )
            )
    try:
        return _apply_ops(raw, ops)
    except SurgeryError:
        log_event("surgery_restore_apply_failed")
        return raw


# Delta types whose payload is model output we may rewrite, and the field
# carrying it.  ``input_json_delta`` is a fragment of a tool call's JSON input,
# so originals spliced into it must be JSON-escaped (``_json_fragment``).
_DELTA_FIELDS = {"text_delta": "text", "input_json_delta": "partial_json"}


def _json_fragment(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)[1:-1]


class SSETextRestorer:
    """Restore placeholders across Anthropic SSE content deltas.

    ``text_delta`` text and ``input_json_delta`` partial JSON are rewritten
    (tool calls carry placeholders too: a model asked to edit a file that
    contained a redacted key writes the placeholder back).  Every other event
    — including ``thinking_delta`` / ``signature_delta`` — passes through
    untouched.  Each content block has its own hold-back buffer, released as
    a synthetic delta just before that block's ``content_block_stop`` so held
    text never migrates into another block.

    SSE framing: an ``event:`` line is held until its ``data:`` line arrives,
    so a synthetic frame (which carries its own ``event:`` line — the
    Anthropic SDKs dispatch on it) can be inserted before a whole frame
    rather than between a frame's two lines.
    """

    def __init__(self, reverse_map: dict[str, str]) -> None:
        self._map = reverse_map or {}
        self._line = bytearray()
        self._pending_event: bytes | None = None
        self._blocks: dict[int, tuple[str, StreamRestorer]] = {}

    def feed_chunk(self, chunk: bytes) -> bytes:
        self._line += chunk
        out = bytearray()
        while True:
            nl = self._line.find(b"\n")
            if nl == -1:
                break
            line = bytes(self._line[: nl + 1])
            del self._line[: nl + 1]
            out += self._process_line(line)
        return bytes(out)

    def flush(self) -> bytes:
        rest = bytes(self._line)
        self._line.clear()
        out = self._process_line(rest) if rest else b""
        for index in list(self._blocks):
            out += self._release(index)
        if self._pending_event is not None:
            out += self._pending_event
            self._pending_event = None
        return out

    def _release(self, index: int) -> bytes:
        """Emit what a block still holds (it ended mid-placeholder) verbatim."""
        entry = self._blocks.pop(index, None)
        if entry is None:
            return b""
        delta_type, restorer = entry
        held = restorer.flush()
        if not held:
            return b""
        log_event("surgery_stream_held_unterminated")
        event = {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": delta_type, _DELTA_FIELDS[delta_type]: held},
        }
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        return b"event: content_block_delta\ndata: " + payload.encode("utf-8") + b"\n\n"

    def _restorer(self, index: int, delta_type: str) -> StreamRestorer:
        entry = self._blocks.get(index)
        if entry is None:
            escape = _json_fragment if delta_type == "input_json_delta" else None
            entry = (delta_type, StreamRestorer(self._map, escape=escape))
            self._blocks[index] = entry
        return entry[1]

    def _process_line(self, line: bytes) -> bytes:
        if line.startswith(b"event:"):
            previous, self._pending_event = self._pending_event or b"", line
            return previous
        pending, self._pending_event = self._pending_event or b"", None
        if not line.startswith(b"data:"):
            return pending + line
        payload = line[5:].strip(b" \r\n")
        try:
            event = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return pending + line
        if not isinstance(event, dict):
            return pending + line
        index = event.get("index", 0)
        if not isinstance(index, int):
            return pending + line
        if event.get("type") == "content_block_stop":
            return self._release(index) + pending + line
        if event.get("type") != "content_block_delta" or not self._map:
            return pending + line
        delta = event.get("delta")
        if not isinstance(delta, dict):
            return pending + line
        delta_type = delta.get("type")
        field_name = _DELTA_FIELDS.get(delta_type) if isinstance(delta_type, str) else None
        value = delta.get(field_name) if field_name else None
        if field_name is None or not isinstance(value, str):
            return pending + line
        new_value = self._restorer(index, str(delta_type)).feed(value)
        if new_value == value:
            return pending + line
        delta[field_name] = new_value
        new_payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        tail = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        return pending + b"data: " + new_payload + tail
