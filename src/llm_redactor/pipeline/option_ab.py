"""Option A+B pipeline: route locally when possible, redact the rest.

The recommended default for most deployments. Trivial requests never
leave the device (Option A); complex requests are redacted (Option B)
before forwarding to the cloud.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..detect.orchestrator import detect_all
from ..detect.types import Span
from ..pipeline.option_a import classify
from ..redact.placeholder import RedactionResult, redact
from ..redact.restore import restore
from ..transport.cloud import forward_chat_completion


@dataclass
class OptionABPipelineResult:
    """Result of running Option A+B on a request."""

    response: dict[str, Any]
    route: str  # "local" or "cloud"
    detections: list[Span]
    redaction: RedactionResult | None
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionABPipeline:
    """Option A+B: route locally if trivial, redact + cloud if complex."""

    config: Config
    use_ner: bool = True
    _stats: dict[str, int] = field(default_factory=lambda: {
        "requests": 0,
        "routed_local": 0,
        "routed_cloud": 0,
        "detections": 0,
    })

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionABPipelineResult:
        """Classify, then route locally or redact + forward."""
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        text = " ".join(
            m.get("content", "")
            for m in messages
            if isinstance(m.get("content"), str)
        )

        # Stage 1: Option A classification.
        ollama_endpoint = self.config.local_model.endpoint
        ollama_model = self.config.local_model.chat_model

        classification = await classify(
            text, endpoint=ollama_endpoint, model=ollama_model,
        )

        if classification == "TRIVIAL":
            # Answer locally — nothing leaves the device.
            self._stats["routed_local"] += 1
            from ..pipeline.option_a import answer_locally

            local_answer = await answer_locally(
                text, endpoint=ollama_endpoint, model=ollama_model,
            )

            response = {
                "choices": [
                    {"message": {"role": "assistant", "content": local_answer}}
                ],
            }

            return OptionABPipelineResult(
                response=response,
                route="local",
                detections=[],
                redaction=None,
                options_applied=["A"],
                leak_audit={
                    "outgoing_bytes": 0,
                    "sensitive_tokens_detected": 0,
                    "sensitive_tokens_sent": 0,
                },
            )

        # Stage 2: Option B redaction for complex requests.
        self._stats["routed_cloud"] += 1
        all_detections: list[Span] = []
        redaction_results: dict[int, RedactionResult] = {}

        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue
            spans = detect_all(content, use_ner=self.use_ner)
            all_detections.extend(spans)
            if spans:
                result = redact(content, spans)
                redaction_results[i] = result

        self._stats["detections"] += len(all_detections)

        # Build outgoing body.
        outgoing = dict(body)
        outgoing_messages = list(messages)
        for i, rr in redaction_results.items():
            outgoing_messages[i] = {**messages[i], "content": rr.redacted_text}
        outgoing["messages"] = outgoing_messages
        outgoing.pop("extra_body", None)

        cloud_response = await forward_chat_completion(outgoing, self.config.cloud_target)

        # Restore placeholders.
        combined_reverse_map: dict[str, str] = {}
        for rr in redaction_results.values():
            combined_reverse_map.update(rr.reverse_map)

        if combined_reverse_map and "choices" in cloud_response:
            for choice in cloud_response["choices"]:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    msg["content"] = restore(content, combined_reverse_map)

        outgoing_text = " ".join(
            m.get("content", "") for m in outgoing_messages
            if isinstance(m.get("content"), str)
        )
        sensitive_sent = sum(1 for s in all_detections if s.text in outgoing_text)

        return OptionABPipelineResult(
            response=cloud_response,
            route="cloud",
            detections=all_detections,
            redaction=next(iter(redaction_results.values()), None),
            options_applied=["A", "B"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "sensitive_tokens_sent": sensitive_sent,
            },
        )
