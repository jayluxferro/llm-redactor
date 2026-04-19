"""Option B pipeline: detect → redact → forward → restore."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, cast

from ..config import Config
from ..detect.orchestrator import detect_all, detect_all_validated
from ..detect.types import Span
from ..observability import log_event
from ..redact.placeholder import RedactionResult, redact
from ..redact.restore import restore
from ..transport.cloud import forward_chat_completion


class _SessionTagUnset:
    """Sentinel: caller did not pass ``session_tag`` (auto-generate or omit)."""

    __slots__ = ()


_SESSION_TAG_UNSET = _SessionTagUnset()


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

    async def detect_spans(self, text: str) -> list[Span]:
        """Run configured detectors (optional LLM validation via Ollama)."""
        if self.config.pipeline.llm_validation.enabled:
            model = self.config.pipeline.llm_validation.model or self.config.local_model.chat_model
            return await detect_all_validated(
                text,
                use_ner=self.use_ner,
                ollama_endpoint=self.config.local_model.endpoint,
                ollama_model=model,
            )
        return detect_all(text, use_ner=self.use_ner)

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

        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            spans = await self.detect_spans(content)
            all_detections.extend(spans)

            if spans:
                result = redact(content, spans, session_tag=placeholder_tag)
                redaction_results[i] = result
                outgoing[i] = {**msg, "content": result.redacted_text}

        return outgoing, redaction_results, all_detections, placeholder_tag

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

        # Leak audit: count sensitive tokens that survived in the outgoing body.
        outgoing_text = " ".join(
            m.get("content", "") for m in outgoing_messages if isinstance(m.get("content"), str)
        )
        sensitive_sent = sum(1 for s in all_detections if s.text in outgoing_text)

        return PipelineResult(
            response=cloud_response,
            detections=all_detections,
            redaction=combined_redaction,
            options_applied=["B"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "sensitive_tokens_sent": sensitive_sent,
            },
        )


class RefusalError(Exception):
    """Raised when strict mode refuses a request."""

    def __init__(self, reason: str, spans: list[Span]) -> None:
        self.reason = reason
        self.spans = spans
        super().__init__(f"Refused: {reason} ({len(spans)} low-confidence spans)")
