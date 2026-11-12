"""Option B pipeline: detect → redact → forward → restore."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, cast

from ..config import Config
from ..detect.orchestrator import detect_candidates, detect_validated, finalize_spans
from ..detect.types import Span
from ..observability import log_event
from ..redact.placeholder import PlaceholderGenerator, RedactionResult, redact
from ..redact.restore import restore
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

    async def redact_chat_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        session_tag: str | None | _SessionTagUnset = _SESSION_TAG_UNSET,
    ) -> tuple[list[dict[str, Any]], dict[int, RedactionResult], list[Span], str | None]:
        """Detect/redact string ``content`` for each message.

        If ``session_tag`` is omitted, a new tag is generated when
        ``placeholder_request_tag`` is enabled. Pass an explicit tag (or
        ``None``) to bind multiple parts of one upstream request.
        """
        if session_tag is _SESSION_TAG_UNSET:
            placeholder_tag = self.request_placeholder_tag()
        else:
            placeholder_tag = cast(str | None, session_tag)
        outgoing = list(messages)
        redaction_results: dict[int, RedactionResult] = {}
        all_detections: list[Span] = []
        gen = PlaceholderGenerator(session_tag=placeholder_tag)

        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                spans = await self.detect_spans(content)
                all_detections.extend(spans)
                if spans:
                    result = redact(content, spans, gen=gen)
                    redaction_results[i] = result
                    outgoing[i] = {**msg, "content": result.redacted_text}
            elif isinstance(content, list):
                # Content parts ([{"type": "text", "text": ...}, {"type":
                # "image_url", ...}]): what multimodal and most current SDK
                # clients send.  These used to be skipped entirely, i.e.
                # forwarded unredacted.
                parts, merged = await self._redact_parts(content, gen, all_detections)
                if merged is not None:
                    redaction_results[i] = merged
                    outgoing[i] = {**msg, "content": parts}

        return outgoing, redaction_results, all_detections, placeholder_tag

    async def _redact_parts(
        self, parts: list[Any], gen: PlaceholderGenerator, detections: list[Span]
    ) -> tuple[list[Any], RedactionResult | None]:
        """Redact the ``text`` parts of a content list; others pass unchanged."""
        out: list[Any] = []
        merged: RedactionResult | None = None
        for part in parts:
            text = part.get("text") if isinstance(part, dict) else None
            if not (isinstance(part, dict) and part.get("type") == "text" and text):
                out.append(part)
                continue
            spans = await self.detect_spans(text)
            detections.extend(spans)
            if not spans:
                out.append(part)
                continue
            result = redact(text, spans, gen=gen)
            out.append({**part, "text": result.redacted_text})
            if merged is None:
                merged = RedactionResult("", {}, [])
            merged.reverse_map.update(result.reverse_map)
            merged.placeholders.extend(result.placeholders)
        if merged is not None:
            merged.redacted_text = "\n".join(_message_text(p) for p in out)
        return out, merged

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

        (
            outgoing_messages,
            redaction_results,
            all_detections,
            ph_tag,
        ) = await self.redact_chat_messages(messages)

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

        # Build the combined reverse map from all redacted messages.
        combined_reverse_map: dict[str, str] = {}
        combined_redaction: RedactionResult | None = None
        for rr in redaction_results.values():
            combined_reverse_map.update(rr.reverse_map)
        if combined_reverse_map and redaction_results:
            first = next(iter(redaction_results.values()))
            combined_redaction = first

        # Restore placeholders in the response content.
        if combined_reverse_map and "choices" in cloud_response:
            for choice in cloud_response["choices"]:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    msg["content"] = restore(content, combined_reverse_map)

        # Leak audit: after redaction the original span text should never
        # appear in the outgoing body. Non-zero = redaction failure.
        outgoing_text = " ".join(_message_text(m.get("content")) for m in outgoing_messages)
        survived = sum(1 for s in all_detections if s.text in outgoing_text)

        return PipelineResult(
            response=cloud_response,
            detections=all_detections,
            redaction=combined_redaction,
            options_applied=["B"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "original_span_text_survived": survived,
            },
        )


def _message_text(content: Any) -> str:
    """The text of a string ``content``, a text part, or a list of parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text = content.get("text")
        return text if content.get("type") == "text" and isinstance(text, str) else ""
    if isinstance(content, list):
        return " ".join(_message_text(p) for p in content)
    return ""


class RefusalError(Exception):
    """Raised when strict mode refuses a request."""

    def __init__(self, reason: str, spans: list[Span]) -> None:
        self.reason = reason
        self.spans = spans
        super().__init__(f"Refused: {reason} ({len(spans)} low-confidence spans)")
