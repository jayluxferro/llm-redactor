"""Presidio-backed NER detector for PII."""

from __future__ import annotations

from .types import Span

# Presidio is heavy — lazy-load to avoid ~1s startup penalty on import.
_analyzer = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Load spaCy model directly to avoid presidio calling spacy.cli.download(),
        # which makes a network request to check compatibility. The model is already
        # installed; we don't need the compatibility check.
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    return _analyzer


# Map presidio entity types to our kind taxonomy.
PRESIDIO_KIND_MAP: dict[str, str] = {
    "PERSON": "person",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "CREDIT_CARD": "credit_card",
    "IBAN_CODE": "iban",
    "IP_ADDRESS": "ip_address",
    "US_SSN": "ssn",
    "LOCATION": "location",
    "DATE_TIME": "date_time",
    "NRP": "nationality",
    "MEDICAL_LICENSE": "medical_license",
    "URL": "url",
}


def detect_ner(text: str, language: str = "en") -> list[Span]:
    """Run presidio analyzer and return detected spans."""
    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language=language)

    spans: list[Span] = []
    seen: set[tuple[int, int]] = set()

    for result in results:
        key = (result.start, result.end)
        if key in seen:
            continue
        seen.add(key)

        kind = PRESIDIO_KIND_MAP.get(result.entity_type, result.entity_type.lower())
        spans.append(
            Span(
                start=result.start,
                end=result.end,
                kind=kind,
                confidence=result.score,
                text=text[result.start : result.end],
                source="ner",
            )
        )

    return spans
