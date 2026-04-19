"""Option C pipeline: detect → redact (B) → rephrase → validate → forward → restore.

Option C layers on top of Option B. After B's span-level redaction,
C rewrites the remaining text through a local model to strip implicit
identifying information that B's detectors can't catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..detect.orchestrator import detect_all
from ..detect.types import Span, filter_by_categories
from ..redact.placeholder import RedactionResult, redact
from ..redact.restore import restore
from ..rephrase.local_model import RephraseResult, rephrase
from ..rephrase.validator import ValidationResult, validate_rephrase
from ..transport.cloud import forward_chat_completion


@dataclass
class OptionCPipelineResult:
    """Result of running Option B+C on a chat completion request."""

    response: dict[str, Any]
    detections: list[Span]
    redaction: RedactionResult | None
    rephrase_result: RephraseResult | None
    validation: ValidationResult | None
    rephrase_used: bool  # False if validator rejected and we fell back to B-only
    options_applied: list[str]
    leak_audit: dict[str, Any]


@dataclass
class OptionCPipeline:
    """Option B+C: redact spans, then rephrase remaining text via local model."""

    config: Config
    use_ner: bool = True
    _stats: dict[str, int] = field(
        default_factory=lambda: {
            "requests": 0,
            "detections": 0,
            "rephrases": 0,
            "rephrase_rollbacks": 0,
        }
    )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self, body: dict[str, Any]) -> OptionCPipelineResult:
        """Run the full B+C pipeline."""
        self._stats["requests"] += 1

        messages = body.get("messages", [])
        all_detections: list[Span] = []
        redaction_results: dict[int, RedactionResult] = {}

        # Stage 1: Detect and redact (Option B).
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            spans = detect_all(content, use_ner=self.use_ner)
            spans = filter_by_categories(spans, self.config.policy.categories)
            all_detections.extend(spans)

            if spans:
                result = redact(content, spans)
                redaction_results[i] = result

        self._stats["detections"] += len(all_detections)

        # Build B-redacted messages.
        b_messages = list(messages)
        for i, red_res in redaction_results.items():
            b_messages[i] = {**messages[i], "content": red_res.redacted_text}

        # Stage 2: Rephrase each user message (Option C).
        rephrase_result: RephraseResult | None = None
        validation: ValidationResult | None = None
        rephrase_used = False
        c_messages = list(b_messages)

        ollama_endpoint = self.config.local_model.endpoint
        ollama_model = self.config.local_model.chat_model

        for i, msg in enumerate(c_messages):
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            self._stats["rephrases"] += 1
            reph_res = await rephrase(
                content,
                endpoint=ollama_endpoint,
                model=ollama_model,
            )
            rephrase_result = reph_res

            # Stage 3: Validate the rephrase.
            require_pass = self.config.pipeline.opt_c_rephrase.require_validator_pass
            vr = validate_rephrase(content, reph_res.rephrased_text)
            validation = vr

            if vr.valid or not require_pass:
                c_messages[i] = {**msg, "content": reph_res.rephrased_text}
                rephrase_used = True
            else:
                # Rollback: keep B-only redaction for this message.
                self._stats["rephrase_rollbacks"] += 1

        # Build the combined reverse map.
        combined_reverse_map: dict[str, str] = {}
        for rr in redaction_results.values():
            combined_reverse_map.update(rr.reverse_map)

        # Build outgoing body.
        outgoing = dict(body)
        outgoing["messages"] = c_messages
        outgoing.pop("extra_body", None)

        # Forward to cloud.
        cloud_response = await forward_chat_completion(outgoing, self.config.cloud_target)

        # Restore placeholders in the response.
        if combined_reverse_map and "choices" in cloud_response:
            for choice in cloud_response["choices"]:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    msg["content"] = restore(content, combined_reverse_map)

        # Leak audit.
        outgoing_text = " ".join(
            m.get("content", "") for m in c_messages if isinstance(m.get("content"), str)
        )
        sensitive_sent = sum(1 for s in all_detections if s.text in outgoing_text)

        options = ["B", "C"] if rephrase_used else ["B"]
        combined_redaction = next(iter(redaction_results.values()), None)

        return OptionCPipelineResult(
            response=cloud_response,
            detections=all_detections,
            redaction=combined_redaction,
            rephrase_result=rephrase_result,
            validation=validation,
            rephrase_used=rephrase_used,
            options_applied=options,
            leak_audit={
                "outgoing_bytes": len(outgoing_text.encode()),
                "sensitive_tokens_detected": len(all_detections),
                "sensitive_tokens_sent": sensitive_sent,
            },
        )
