"""Response-path restoration: substitute placeholders back to originals."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .placeholder import PREFIX, SUFFIX

# Placeholders are ⟨KIND_N·tag⟩, short by construction.  A held span longer
# than this in a streaming restorer cannot be a placeholder.
MAX_PLACEHOLDER_LEN = 128


def restore(text: str, reverse_map: dict[str, str]) -> str:
    """Replace placeholders in the response with their original values.

    Only exact matches are substituted. If the cloud model paraphrased
    a placeholder (e.g. dropped the brackets), we leave it alone — that
    is the safe behaviour.
    """
    result = text
    for placeholder, original in reverse_map.items():
        result = result.replace(placeholder, original)
    return result


def json_fragment(text: str) -> str:
    """``text`` as it must appear inside a JSON string literal (no quotes)."""
    return json.dumps(text, ensure_ascii=False)[1:-1]


def restore_in_json_text(json_text: str, reverse_map: dict[str, str]) -> str:
    """Restore placeholders inside JSON *text* (e.g. tool-call ``arguments``).

    Complete JSON is decoded, restored value by value and re-encoded, which is
    immune to how the producer escaped it: ``json.dumps`` writes ``⟨`` as
    ``\\u27e8`` by default, so plain text replacement silently missed those.
    Unchanged JSON keeps its exact bytes.  Anything that does not parse (a
    fragment) gets text replacement of both spellings, with each original
    JSON-escaped so a quote or newline in it cannot end the string literal.
    """
    if not reverse_map:
        return json_text
    try:
        value = json.loads(json_text)
    except ValueError:
        mapping: dict[str, str] = {}
        for placeholder, original in reverse_map.items():
            escaped = json_fragment(original)
            mapping[placeholder] = escaped
            ascii_form = json.dumps(placeholder)[1:-1]  # ⟨KIND_1⟩
            mapping[ascii_form] = escaped
            mapping[ascii_form.replace("\\u27e8", "\\u27E8").replace("\\u27e9", "\\u27E9")] = (
                escaped
            )
        return restore(json_text, mapping)
    restored = restore_json(value, reverse_map)
    return json_text if restored == value else json.dumps(restored, ensure_ascii=False)


def restore_json(value: Any, reverse_map: dict[str, str]) -> Any:
    """``restore`` applied to every string inside decoded JSON (tool-call inputs)."""
    if not reverse_map:
        return value
    if isinstance(value, str):
        return restore(value, reverse_map)
    if isinstance(value, list):
        return [restore_json(v, reverse_map) for v in value]
    if isinstance(value, dict):
        return {k: restore_json(v, reverse_map) for k, v in value.items()}
    return value


class StreamRestorer:
    """Restore placeholders in text that arrives in pieces (SSE deltas).

    Models stream token by token, so a placeholder usually arrives split
    (``"⟨"``, ``"EMAIL"``, ``"_1"``, ``"⟩"``).  Streamed text cannot be taken
    back, so restoring the accumulated text after the fact would leave the
    already-sent ``⟨EMAIL_1`` in front of the original.  Instead, text from a
    ``⟨`` onwards is held back until its ``⟩`` arrives, or until it grows
    past any possible placeholder and is released verbatim.

    ``escape`` transforms an original before it is inserted, e.g. JSON-escaping
    it when the stream is a fragment of a JSON document (tool-call arguments).
    One instance per independent stream (choice index / content block).
    """

    def __init__(
        self, reverse_map: dict[str, str], *, escape: Callable[[str], str] | None = None
    ) -> None:
        self._map = reverse_map
        self._escape = escape
        self._held = ""

    def feed(self, piece: str) -> str:
        cur = self._held + piece
        self._held = ""
        if not self._map or PREFIX not in cur:
            return cur
        out: list[str] = []
        while cur:
            i = cur.find(PREFIX)
            if i == -1:
                out.append(cur)
                break
            out.append(cur[:i])
            cur = cur[i:]
            close = cur.find(SUFFIX, 1)
            reopen = cur.find(PREFIX, 1)
            if reopen != -1 and (close == -1 or reopen < close):
                # A second "⟨" before any "⟩": the first cannot open a placeholder.
                out.append(cur[:reopen])
                cur = cur[reopen:]
                continue
            if close == -1:
                if len(cur) > MAX_PLACEHOLDER_LEN:
                    out.append(cur)
                else:
                    self._held = cur
                break
            candidate = cur[: close + 1]
            original = self._map.get(candidate)
            if original is None:
                out.append(candidate)
            else:
                out.append(self._escape(original) if self._escape else original)
            cur = cur[close + 1 :]
        return "".join(out)

    def flush(self) -> str:
        """Release held text verbatim (the stream ended mid-placeholder)."""
        held, self._held = self._held, ""
        return held
