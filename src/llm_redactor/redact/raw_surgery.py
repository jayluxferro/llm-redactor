"""Byte-preserving surgical redaction for signed Anthropic bodies.

Anthropic cryptographically signs ``thinking`` / ``redacted_thinking`` blocks
against the exact JSON bytes it served, so any ``json.loads`` / ``json.dumps``
round-trip invalidates them (the API rejects the next turn with a 400).
This module redacts sensitive spans from the *other* string values by editing
the raw bytes directly, leaving signed regions byte-identical.  The same
machinery restores placeholders in raw responses without touching signed
content there either.

Scope rules mirror the non-signed Anthropic path in ``transport/http_proxy``:
only ``messages[*].content`` string values and the ``text`` field of ``text``
content blocks are redacted.  ``thinking`` / ``redacted_thinking`` blocks and
``signature`` fields are never modified.  Placeholders that leak into signed
thinking content are deliberately left in place — mutating them would break
the signature on the client's next turn.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..observability import log_event
from .placeholder import PREFIX as PH_PREFIX
from .placeholder import SUFFIX as PH_SUFFIX

PROTECTED_BLOCK_TYPES = frozenset({"thinking", "redacted_thinking"})
PROTECTED_KEYS = frozenset({"signature"})

# Placeholders are ⟨KIND_N·tag⟩ — short by construction.  A held span longer
# than this in the streaming restorer cannot be a placeholder.
MAX_PLACEHOLDER_LEN = 128


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
class RawRedaction:
    """Outcome of a surgical request redaction."""

    new_raw: bytes
    reverse_map: dict[str, str] = field(default_factory=dict)
    detections: list[object] = field(default_factory=list)
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
) -> int:
    """Scan one JSON value at ``i``; append string tokens. Returns end offset."""
    i = _skip_ws(buf, i)
    if i >= len(buf):
        raise SurgeryError("unexpected end of body")
    b = buf[i]
    if b == 0x22:  # string value
        value, end = _scan_string(buf, i)
        key = path[-1] if path else None
        protected = inherited_protected or (
            isinstance(key, str) and key in PROTECTED_KEYS
        )
        tokens.append(
            StringToken(path=path, value=value, raw_start=i, raw_end=end, protected=protected)
        )
        return end
    if b == 0x7B:  # '{'
        return _scan_object(buf, i, path, inherited_protected, tokens)
    if b == 0x5B:  # '['
        return _scan_array(buf, i, path, inherited_protected, tokens)
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
) -> int:
    i = _skip_ws(buf, i + 1)
    if i < len(buf) and buf[i] == 0x5D:
        return i + 1
    idx = 0
    while True:
        i = _scan_value(buf, i, (*path, idx), inherited_protected, tokens)
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
) -> int:
    i = _skip_ws(buf, i + 1)
    tokens_start = len(tokens)
    block_type: str | None = None
    if i < len(buf) and buf[i] == 0x7D:
        return i + 1
    while True:
        i = _skip_ws(buf, i)
        key, i = _scan_string(buf, i)
        i = _skip_ws(buf, i)
        if i >= len(buf) or buf[i] != 0x3A:
            raise SurgeryError(f"expected ':' at offset {i}")
        i += 1
        value_token_count = len(tokens)
        i = _scan_value(buf, i, (*path, key), inherited_protected, tokens)
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


def _is_redactable(token: StringToken) -> bool:
    """Mirror of the non-signed path's redaction scope."""
    if token.protected or not token.value:
        return False
    p = token.path
    if (
        len(p) == 3
        and p[0] == "messages"
        and isinstance(p[1], int)
        and p[2] == "content"
    ):
        return True
    if (
        len(p) == 5
        and p[0] == "messages"
        and isinstance(p[1], int)
        and p[2] == "content"
        and isinstance(p[3], int)
        and p[4] == "text"
        and token.block_type == "text"
    ):
        return True
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
    detect_spans: Callable[[str], Awaitable[list[object]]],
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
    ops: list[_Op] = []
    for tok in tokens:
        if not _is_redactable(tok):
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


class SSETextRestorer:
    """Restore placeholders across Anthropic SSE ``text_delta`` events.

    Only ``content_block_delta`` events carrying a ``text_delta`` are rewritten
    (they carry no signatures); every other event — including
    ``thinking_delta`` / ``signature_delta`` — passes through untouched.  A
    placeholder split across deltas is held back until it completes.
    """

    def __init__(self, reverse_map: dict[str, str]) -> None:
        self._map = reverse_map or {}
        self._line = bytearray()
        self._held: str | None = None

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
        processed = self._process_line(rest) if rest else b""
        if self._held is not None:
            # Stream ended mid-placeholder: the placeholder never completed,
            # so emit what we held verbatim as a final text delta.
            held = self._held
            self._held = None
            log_event("surgery_stream_held_unterminated")
            synthetic = (
                b"data: "
                + json.dumps(
                    {
                        "type": "content_block_delta",
                        "delta": {"type": "text_delta", "text": held},
                    },
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                + b"\n\n"
            )
            return processed + synthetic
        return processed

    def _process_line(self, line: bytes) -> bytes:
        if not line.startswith(b"data:"):
            return line
        payload = line[5:].strip(b" \r\n")
        try:
            event = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return line
        if not isinstance(event, dict) or event.get("type") != "content_block_delta":
            return line
        delta = event.get("delta")
        if not isinstance(delta, dict) or delta.get("type") != "text_delta":
            return line
        text = delta.get("text")
        if not isinstance(text, str):
            return line
        new_text = self._feed_text(text)
        if new_text == text:
            return line
        delta["text"] = new_text
        new_payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        tail = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        return b"data: " + new_payload + tail

    def _feed_text(self, s: str) -> str:
        if self._held is None and (not self._map or PH_PREFIX not in s):
            return s
        cur = (self._held + s) if self._held is not None else s
        self._held = None
        out: list[str] = []
        while True:
            i = cur.find(PH_PREFIX)
            if i == -1:
                out.append(cur)
                break
            out.append(cur[:i])
            cur = cur[i:]
            j = cur.find(PH_SUFFIX, 1)
            if j == -1:
                if len(cur) > MAX_PLACEHOLDER_LEN:
                    out.append(cur)
                else:
                    self._held = cur
                break
            candidate = cur[: j + 1]
            replacement = self._map.get(candidate)
            out.append(replacement if replacement is not None else candidate)
            cur = cur[j + 1 :]
        return "".join(out)
