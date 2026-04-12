"""Option H pipeline: detect → redact (B) → DP noise → forward → restore.

Layers DP noise on top of Option B. After B's span-level redaction,
H adds word-level noise to blur any residual signal that B's detectors
couldn't catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..detect.orchestrator import detect_all
from ..detect.types import Span
from ..noise.dp import DPResult, inject_noise
from ..redact.placeholder import RedactionResult, redact
from ..redact.restore import restore
from ..transport.cloud import forward_chat_completion


@dataclass
class OptionHPipelineResult:
    """Result of running Option B+H on a request."""

    response: dict[str, Any]
    detections: list[Span]
    redaction: RedactionResult | None
    dp_result: DPResult | None
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionHPipeline:
    """Option B+H: redact spans, then add DP noise to the remainder."""

    config: Config
    use_ner: bool = True
    epsilon: float = 4.0

    async def run(self, body: dict[str, Any]) -> OptionHPipelineResult:
        messages = body.get("messages", [])
        all_detections: list[Span] = []
        redaction_results: dict[int, RedactionResult] = {}

        # Stage 1: Detect and redact (Option B).
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue
            spans = detect_all(content, use_ner=self.use_ner)
            all_detections.extend(spans)
            if spans:
                result = redact(content, spans)
                redaction_results[i] = result

        # Build B-redacted messages.
        b_messages = list(messages)
        for i, rr in redaction_results.items():
            b_messages[i] = {**messages[i], "content": rr.redacted_text}

        # Stage 2: DP noise on each message.
        h_messages = list(b_messages)
        dp_result: DPResult | None = None
        for i, msg in enumerate(h_messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue
            dr = inject_noise(content, epsilon=self.epsilon, seed=hash(content) & 0xFFFFFFFF)
            dp_result = dr
            h_messages[i] = {**msg, "content": dr.noised_text}

        # Reverse map.
        combined_reverse_map: dict[str, str] = {}
        for rr in redaction_results.values():
            combined_reverse_map.update(rr.reverse_map)

        # Forward.
        outgoing = dict(body)
        outgoing["messages"] = h_messages
        outgoing.pop("extra_body", None)
        cloud_response = await forward_chat_completion(outgoing, self.config.cloud_target)

        # Restore placeholders.
        if combined_reverse_map and "choices" in cloud_response:
            for choice in cloud_response["choices"]:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    msg["content"] = restore(content, combined_reverse_map)

        # Leak audit.
        outgoing_text = " ".join(
            m.get("content", "") for m in h_messages if isinstance(m.get("content"), str)
        )
        sensitive_sent = sum(1 for s in all_detections if s.text in outgoing_text)

        return OptionHPipelineResult(
            response=cloud_response,
            detections=all_detections,
            redaction=next(iter(redaction_results.values()), None),
            dp_result=dp_result,
            options_applied=["B", "H"],
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "sensitive_tokens_sent": sensitive_sent,
            },
        )
