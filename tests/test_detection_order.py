"""Detection stage order: detect -> validate -> filter -> merge.

Each test recreates a leak that merging first caused (see
detect/orchestrator.py for the contract).
"""

from __future__ import annotations

from unittest.mock import patch

from llm_redactor.config import Config
from llm_redactor.detect.orchestrator import detect_all_validated, finalize_spans
from llm_redactor.detect.types import Span
from llm_redactor.pipeline.option_b import OptionBPipeline


def _span(text: str, sub: str, kind: str, conf: float, source: str) -> Span:
    start = text.index(sub)
    return Span(start, start + len(sub), kind, conf, sub, source)


def test_policy_filter_runs_before_merge() -> None:
    # Policy wants identity only.  The regex email (contact) overlaps the NER
    # person inside it; merged first, the union took the email's label, was
    # filtered out as "contact", and the person's name leaked.
    text = "write to john.smith@example.org today"
    email = _span(text, "john.smith@example.org", "email", 1.0, "regex")
    person = _span(text, "john.smith", "person", 0.85, "ner")
    spans = finalize_spans([email, person], ["identity"])
    assert [(s.kind, s.text) for s in spans] == [("person", "john.smith")]


async def test_rules_validation_sees_each_detector_span_not_the_union() -> None:
    # A Luhn-valid card overlapped by an NER span: validated after the merge,
    # the rule checked the union's digits, failed, and dropped the card.
    text = "card 4111 1111 1111 1111 9 thanks"
    card = _span(text, "4111 1111 1111 1111", "credit_card", 1.0, "regex")
    noise = _span(text, "1111 1111 9", "phone", 0.6, "ner")
    with patch("llm_redactor.detect.orchestrator.detect_candidates", return_value=[card, noise]):
        spans = await detect_all_validated(text, backend="rules")
    assert len(spans) == 1
    assert "4111 1111 1111 1111" in spans[0].text  # covered, label from the card
    assert spans[0].kind == "credit_card"


async def test_tool_content_ner_switch() -> None:
    from llm_redactor.pipeline import option_b

    seen: list[bool] = []

    def fake(text: str, use_ner: bool = True) -> list[Span]:
        seen.append(use_ner)
        return []

    cfg = Config()
    cfg.pipeline.tool_content_ner = False
    pipeline = OptionBPipeline(config=cfg, use_ner=True)
    option_b._DETECT_CACHE.clear()
    with patch.object(option_b, "detect_candidates", side_effect=fake):
        await pipeline.detect_spans("tool output 7c1e", tool_content=True)
        await pipeline.detect_spans("user message 7c1e")
    assert seen == [False, True]  # NER skipped for tool content only
