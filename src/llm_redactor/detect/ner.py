"""Presidio-backed NER detector for PII.

The spaCy model is configurable:
  - en_core_web_sm (default): fast, lower accuracy
  - en_core_web_trf: transformer-based, much better disambiguation,
    requires PyTorch (~500MB extra dependencies)
  - xx_ent_wiki_sm: multilingual, catches non-English names
"""

from __future__ import annotations

from .types import Span

# Presidio is heavy — lazy-load to avoid ~1s startup penalty on import.
_analyzer = None
_model_name: str = "en_core_web_sm"

# Minimum confidence threshold for NER results.
# Presidio often returns low-confidence matches that are false positives.
NER_CONFIDENCE_FLOOR: float = 0.5


def configure_ner(*, model_name: str | None = None, confidence_floor: float | None = None) -> None:
    """Configure NER before first use. Must be called before _get_analyzer()."""
    global _model_name, NER_CONFIDENCE_FLOOR, _analyzer
    if model_name is not None:
        _model_name = model_name
        _analyzer = None  # force re-init with new model
    if confidence_floor is not None:
        NER_CONFIDENCE_FLOOR = confidence_floor


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": _model_name}],
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
    """Run presidio analyzer and return detected spans.

    Spans below NER_CONFIDENCE_FLOOR are dropped to reduce false positives.
    """
    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language=language)

    spans: list[Span] = []
    seen: set[tuple[int, int]] = set()

    for result in results:
        # Drop low-confidence results.
        if result.score < NER_CONFIDENCE_FLOOR:
            continue

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
