"""Option B pipeline: detect → redact → forward → restore."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..detect.orchestrator import detect_all
from ..detect.types import Span
from ..redact.placeholder import RedactionResult, redact
from ..redact.restore import restore
from ..transport.cloud import forward_chat_completion


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
    _stats: dict[str, int] = field(default_factory=lambda: {
        "requests": 0,
        "detections": 0,
        "refusals": 0,
    })

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(
        self,
        body: dict[str, Any],
        upstream_headers: dict[str, str] | None = None,
    ) -> PipelineResult:
        """Run the full Option B pipeline on a chat completion request body."""
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        all_detections: list[Span] = []
        redaction_results: dict[int, RedactionResult] = {}

        # Detect and redact each message's content.
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            spans = detect_all(
                content,
                use_ner=self.use_ner,
            )
            all_detections.extend(spans)

            if spans:
                result = redact(content, spans)
                redaction_results[i] = result

        self._stats["detections"] += len(all_detections)

        # Check strict mode: refuse if any detection has low confidence.
        if self.config.pipeline.opt_b_redact.strict:
            low_conf = [s for s in all_detections if s.confidence < 0.5]
            if low_conf:
                self._stats["refusals"] += 1
                raise RefusalError(
                    reason="low_confidence_detection",
                    spans=low_conf,
                )

        # Build the outgoing body with redacted messages.
        outgoing = dict(body)
        outgoing_messages = list(messages)
        for i, rr in redaction_results.items():
            outgoing_messages[i] = {
                **messages[i],
                "content": rr.redacted_text,
            }
        outgoing["messages"] = outgoing_messages

        # Strip any redactor-specific fields before forwarding.
        outgoing.pop("extra_body", None)

        # Forward to cloud.
        cloud_response = await forward_chat_completion(
            outgoing, self.config.cloud_target,
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
        sensitive_sent = sum(
            1 for s in all_detections
            if s.text in outgoing_text
        )

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
