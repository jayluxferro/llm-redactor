"""Tests for the rephrase validator (offline, no Ollama needed)."""

from __future__ import annotations

from llm_redactor.rephrase.validator import (
    extract_technical_terms,
    validate_rephrase,
)


def test_extract_technical_terms():
    text = "Help me debug a Python script that uses FastAPI and PostgreSQL."
    terms = extract_technical_terms(text)
    term_lower = {t.lower() for t in terms}
    assert "python" in term_lower
    assert "fastapi" in term_lower
    assert "postgresql" in term_lower
    assert "debug" in term_lower


def test_validate_preserves_all_terms():
    original = "Debug this Python FastAPI endpoint that queries PostgreSQL."
    rephrased = "Debug this Python FastAPI endpoint that queries PostgreSQL."
    result = validate_rephrase(original, rephrased)
    assert result.valid
    assert result.survival_rate == 1.0
    assert result.dropped_terms == []


def test_validate_catches_dropped_terms():
    original = "Debug this Python FastAPI endpoint that queries PostgreSQL."
    rephrased = "Look at this web service that talks to a database."
    result = validate_rephrase(original, rephrased)
    assert len(result.dropped_terms) > 0
    # Should drop Python, FastAPI, PostgreSQL, debug, endpoint, query
    dropped_lower = {t.lower() for t in result.dropped_terms}
    assert "python" in dropped_lower
    assert "fastapi" in dropped_lower


def test_validate_no_technical_terms():
    original = "Send the report to Alice at Acme Corp."
    rephrased = "Send the report to a person at a company."
    result = validate_rephrase(original, rephrased)
    # No technical terms to check → valid by default.
    assert result.valid
    assert result.survival_rate == 1.0


def test_validate_case_insensitive():
    original = "Deploy this Docker container to AWS."
    rephrased = "deploy this docker container to aws."
    result = validate_rephrase(original, rephrased)
    assert result.valid
    assert result.survival_rate == 1.0
