"""Detector availability must not turn a proxy request into a 500."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from llm_redactor.detect.orchestrator import detect_all, detect_all_validated


def test_detect_all_keeps_regex_results_when_ner_fails():
    with patch("llm_redactor.detect.orchestrator.detect_ner", side_effect=RuntimeError("no model")):
        spans = detect_all("mail alice@example.com", use_ner=True)
    assert [span.kind for span in spans] == ["email"]


@pytest.mark.asyncio
async def test_validated_detection_keeps_regex_results_when_local_services_fail():
    with (
        patch("llm_redactor.detect.orchestrator.detect_ner", side_effect=RuntimeError("no model")),
        patch("llm_redactor.detect.llm_validator.validate_spans", side_effect=RuntimeError("no ollama")),
    ):
        spans = await detect_all_validated("mail alice@example.com", use_ner=True)
    assert [span.kind for span in spans] == ["email"]
