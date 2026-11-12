"""Option B pipeline: detect → redact → forward → restore."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, cast

from ..config import Config
from ..detect.orchestrator import detect_candidates, detect_validated, finalize_spans
from ..detect.types import Span
from ..observability import log_event
from ..redact.placeholder import PlaceholderGenerator, RedactionResult, redact
from ..redact.restore import restore, restore_in_json_text
from ..transport.cloud import forward_chat_completion


class _SessionTagUnset:
    """Sentinel: client did not pass ``session_tag`` (auto-generate or omit)."""

    __slots__ = ()


_SESSION_TAG_UNSET = _SessionTagUnset()

# In-memory LRU cache for detection results.  Agent clients resend the whole
# conversation every turn (system prompt, every earlier tool result), so
# almost every string in a request was already scanned last turn.  NER costs
# ~3 s per 100 KB of code, so a miss is expensive: the cache must hold a long
# session's worth of strings.  Keys are 16-byte digests (memory stays flat
# however large the texts are) plus the detection settings, so two pipelines
# with different use_ner / validation settings never share results.
_DETECT_CACHE: OrderedDict[tuple[object, ...], list[Span]] = OrderedDict()
_DETECT_CACHE_MAX = 16_384


def _cache_key(text: str, *settings: object) -> tuple[object, ...]:
    # surrogatepass: JSON bodies can carry lone surrogates ("\ud800").
    digest = hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=16).digest()
    return (*settings, digest)


def _cache_detect(key: tuple[object, ...], spans: list[Span]) -> None:
    _DETECT_CACHE[key] = spans
    _DETECT_CACHE.move_to_end(key)
    while len(_DETECT_CACHE) > _DETECT_CACHE_MAX:
        _DETECT_CACHE.popitem(last=False)


def _cached_detect(key: tuple[object, ...]) -> list[Span] | None:
    if key in _DETECT_CACHE:
        _DETECT_CACHE.move_to_end(key)
        return _DETECT_CACHE[key]
    return None


@dataclass
class PipelineResult:
    """Result of running Option B on a chat completion request."""

    response: dict[str, Any]
    detections: list[Span]
    redaction: RedactionResult | None
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionBPipeline:
    """Detect sensitive spans, redact, forward to cloud, restore."""

    config: Config
    use_ner: bool = True
    _stats: dict[str, int] = field(
        default_factory=lambda: {
            "requests": 0,
            "detections": 0,
            "refusals": 0,
            "signed_passthrough": 0,
            "signed_surgical": 0,
            "surgery_failed": 0,
            "whole_token_fallback": 0,
            "tools_bypass": 0,
        }
    )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def request_placeholder_tag(self) -> str | None:
        """Per-request token embedded in placeholders when enabled in config."""
        if not self.config.pipeline.placeholder_request_tag:
            return None
        return secrets.token_hex(4)

    async def detect_spans(self, text: str, *, tool_content: bool = False) -> list[Span]:
        """Detect (cached), then apply the policy filter and the union merge.

        The cache holds *unmerged* validated spans: the policy filter has to
        run before the merge (see detect/orchestrator.py), and both are cheap.

        ``tool_content`` marks text produced by tools (tool results, tool-call
        arguments).  ``pipeline.tool_content_ner: false`` turns NER off for it
        (regex detection always runs): NER on source code is slow and tags
        identifiers as organisations or people.
        """
        settings = self.config.pipeline
        use_ner = self.use_ner and (settings.tool_content_ner or not tool_content)
        validation = settings.llm_validation
        model = validation.model or self.config.local_model.chat_model
        key = _cache_key(text, use_ner, validation.enabled, validation.backend, model)
        spans = _cached_detect(key)
        if spans is None:
            if validation.enabled:
                spans = await detect_validated(
                    text,
                    use_ner=use_ner,
                    ollama_endpoint=self.config.local_model.endpoint,
                    ollama_model=model,
                    backend=validation.backend,
                )
            else:
                # Offload blocking regex+NER off the event loop.
                spans = await asyncio.to_thread(detect_candidates, text, use_ner)
            _cache_detect(key, spans)
        return finalize_spans(spans, self.config.policy.categories)

    def scrubber(self, session_tag: str | None) -> RequestScrubber:
        """A scrubber for one upstream request (one placeholder namespace)."""
        return RequestScrubber(self, PlaceholderGenerator(session_tag=session_tag))

    async def redact_chat_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        session_tag: str | None | _SessionTagUnset = _SESSION_TAG_UNSET,
    ) -> tuple[list[dict[str, Any]], RequestScrubber, str | None]:
        """Redact every model-visible string of OpenAI-format messages.

        Covers string content, ``text`` content parts, ``tool`` / ``function``
        role results, assistant ``tool_calls[].function.arguments`` and the
        legacy ``function_call``.  Tool-bearing requests used to bypass the
        pipeline entirely (``tools_policy: bypass`` was the default), so most
        agent traffic on this path went out unredacted; tool *schemas*
        (``tools`` / ``functions``) are still forwarded untouched.

        If ``session_tag`` is omitted, a new tag is generated when
        ``placeholder_request_tag`` is enabled. Pass an explicit tag (or
        ``None``) to bind multiple parts of one upstream request.
        """
        if session_tag is _SESSION_TAG_UNSET:
            placeholder_tag = self.request_placeholder_tag()
        else:
            placeholder_tag = cast(str | None, session_tag)
        scrub = self.scrubber(placeholder_tag)
        outgoing = [
            await self._redact_message(msg, scrub) if isinstance(msg, dict) else msg
            for msg in messages
        ]
        return outgoing, scrub, placeholder_tag

    async def _redact_message(self, msg: dict[str, Any], scrub: RequestScrubber) -> dict[str, Any]:
        tool_role = msg.get("role") in ("tool", "function")
        out = dict(msg)
        content = msg.get("content")
        if isinstance(content, str):
            out["content"] = await scrub.text(content, tool_content=tool_role)
        elif isinstance(content, list):
            # Content parts ([{"type": "text", ...}, {"type": "image_url", ...}]),
            # what multimodal and most current SDK clients send.
            out["content"] = [await scrub.part(part, tool_content=tool_role) for part in content]
        calls = msg.get("tool_calls")
        if isinstance(calls, list):
            out["tool_calls"] = [await scrub.tool_call(call) for call in calls]
        legacy = msg.get("function_call")
        if isinstance(legacy, dict) and isinstance(legacy.get("arguments"), str):
            arguments = await scrub.json_text(legacy["arguments"])
            out["function_call"] = {**legacy, "arguments": arguments}
        return out if out != msg else msg

    async def run(
        self,
        body: dict[str, Any],
        upstream_headers: dict[str, str] | None = None,
        strict: bool | None = None,
    ) -> PipelineResult:
        """Run the full Option B pipeline on a chat completion request body.

        *strict* overrides ``opt_b_redact.strict`` for this request when not None.
        """
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        outgoing_messages, scrub, ph_tag = await self.redact_chat_messages(messages)
        all_detections = scrub.detections

        log_event(
            "pipeline_redact_prepared",
            message_count=len(messages),
            detections=len(all_detections),
            placeholder_tag=bool(ph_tag),
            llm_validation=self.config.pipeline.llm_validation.enabled,
        )

        self._stats["detections"] += len(all_detections)

        # Check strict mode: refuse if any detection has low confidence.
        use_strict = strict if strict is not None else self.config.pipeline.opt_b_redact.strict
        if use_strict:
            low_conf = [s for s in all_detections if s.confidence < 0.5]
            if low_conf:
                self._stats["refusals"] += 1
                raise RefusalError(
                    reason="low_confidence_detection",
                    spans=low_conf,
                )

        # Build the outgoing body with redacted messages.
        outgoing = dict(body)
        outgoing["messages"] = outgoing_messages

        # Strip any redactor-specific fields before forwarding.
        outgoing.pop("extra_body", None)

        # Forward to cloud.
        cloud_response = await forward_chat_completion(
            outgoing,
            self.config.cloud_target,
            upstream_headers=upstream_headers,
        )

        # Restore placeholders in the response: text and tool-call arguments.
        if scrub.reverse_map:
            for choice in cloud_response.get("choices") or []:
                if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
                    restore_openai_message(choice["message"], scrub.reverse_map)

        # Leak audit: after redaction the original span text should never
        # appear in the outgoing body. Non-zero = redaction failure.
        outgoing_text = "\n".join(_strings(outgoing_messages))
        survived = sum(1 for s in all_detections if s.text in outgoing_text)

        return PipelineResult(
            response=cloud_response,
            detections=all_detections,
            redaction=scrub.result(outgoing_text) if scrub.reverse_map else None,
            options_applied=["B"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "original_span_text_survived": survived,
            },
        )


class RequestScrubber:
    """Redacts the strings of ONE upstream request.

    One placeholder generator per request keeps a value's placeholder the same
    everywhere it appears (system prompt, a tool result, a later tool call),
    and the accumulated reverse map is what restores the response.
    """

    def __init__(self, pipeline: OptionBPipeline, gen: PlaceholderGenerator) -> None:
        self._pipeline = pipeline
        self._gen = gen
        self.reverse_map: dict[str, str] = {}
        self.placeholders: list[str] = []
        self.detections: list[Span] = []

    async def text(self, text: str, *, tool_content: bool = False) -> str:
        if not text:
            return text
        spans = await self._pipeline.detect_spans(text, tool_content=tool_content)
        if not spans:
            return text
        self.detections.extend(spans)
        result = redact(text, spans, gen=self._gen)
        self.reverse_map.update(result.reverse_map)
        self.placeholders.extend(result.placeholders)
        return result.redacted_text

    async def json_value(self, value: Any, *, tool_content: bool = True) -> Any:
        """Every string inside decoded JSON (tool inputs), structure untouched."""
        if isinstance(value, str):
            return await self.text(value, tool_content=tool_content)
        if isinstance(value, list):
            return [await self.json_value(v, tool_content=tool_content) for v in value]
        if isinstance(value, dict):
            items = value.items()
            return {k: await self.json_value(v, tool_content=tool_content) for k, v in items}
        return value

    async def json_text(self, raw: str, *, tool_content: bool = True) -> str:
        """Redact the string values inside JSON *text* (tool-call ``arguments``).

        Decoded first, so a span can never cut through JSON syntax or an
        escape sequence; unchanged arguments keep their exact bytes.  Text
        that is not valid JSON is redacted as plain text.
        """
        try:
            value = json.loads(raw)
        except ValueError:
            return await self.text(raw, tool_content=tool_content)
        redacted = await self.json_value(value, tool_content=tool_content)
        return raw if redacted == value else json.dumps(redacted, ensure_ascii=False)

    async def part(self, part: Any, *, tool_content: bool = False) -> Any:
        """A content part: ``text`` (chat), or ``input_text``/``output_text`` and the
        reasoning item's ``summary_text``/``reasoning_text`` (responses)."""
        if (
            isinstance(part, dict)
            and part.get("type") in _TEXT_PART_TYPES
            and isinstance(part.get("text"), str)
        ):
            return {**part, "text": await self.text(part["text"], tool_content=tool_content)}
        return part

    async def tool_call(self, call: Any) -> Any:
        function = call.get("function") if isinstance(call, dict) else None
        if isinstance(function, dict) and isinstance(function.get("arguments"), str):
            arguments = await self.json_text(function["arguments"])
            return {**call, "function": {**function, "arguments": arguments}}
        return call

    def result(self, redacted_text: str) -> RedactionResult:
        return RedactionResult(redacted_text, dict(self.reverse_map), list(self.placeholders))


_TEXT_PART_TYPES = frozenset(
    {"text", "input_text", "output_text", "summary_text", "reasoning_text"}
)


def restore_openai_message(message: dict[str, Any], reverse_map: dict[str, str]) -> None:
    """Restore placeholders in a chat-completion message, in place."""
    content = message.get("content")
    if isinstance(content, str):
        message["content"] = restore(content, reverse_map)
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part["text"] = restore(part["text"], reverse_map)
    for call in message.get("tool_calls") or []:
        function = call.get("function") if isinstance(call, dict) else None
        if isinstance(function, dict) and isinstance(function.get("arguments"), str):
            function["arguments"] = restore_in_json_text(function["arguments"], reverse_map)
    legacy = message.get("function_call")
    if isinstance(legacy, dict) and isinstance(legacy.get("arguments"), str):
        legacy["arguments"] = restore_in_json_text(legacy["arguments"], reverse_map)


def _strings(value: Any) -> list[str]:
    """Every string inside a JSON-like value (for the leak audit)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


class RefusalError(Exception):
    """Raised when strict mode refuses a request."""

    def __init__(self, reason: str, spans: list[Span]) -> None:
        self.reason = reason
        self.spans = spans
        super().__init__(f"Refused: {reason} ({len(spans)} low-confidence spans)")
