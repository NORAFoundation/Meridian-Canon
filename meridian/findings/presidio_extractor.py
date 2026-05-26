"""Microsoft Presidio-backed entity extractor for EntityMasker.

Drop-in replacement for enm._default_extract.
Install: pip install presidio-analyzer presidio-anonymizer spacy
         python -m spacy download en_core_web_lg
"""
from __future__ import annotations

from functools import lru_cache

try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer
    _PRESIDIO_AVAILABLE = True
except ImportError:
    _PRESIDIO_AVAILABLE = False

# Legal-domain entity types to recognize
_ENTITY_TYPES = [
    "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN",
    "US_PASSPORT", "CREDIT_CARD", "IP_ADDRESS", "URL",
    "LOCATION", "DATE_TIME", "NRP", "MEDICAL_LICENSE",
]

# Legal-domain custom patterns
_LEGAL_PATTERNS_DEF = [
    # Wisconsin/Minnesota case numbers, e.g. YYYYJCNNNNNN (CHIPS), YYYYCFNNNNNN (criminal), YY-CF-YY-NNN (MN)
    ("WI_CASE_NUMBER", r"\b\d{4}[A-Z]{2}\d{6}\b", 0.9),
    ("MN_CASE_NUMBER", r"\b\d{2}-[A-Z]+-\d{2}-\d+\b", 0.9),
    # Bates numbers
    ("BATES_NUMBER", r"\b[A-Z]{2,6}\d{4,10}\b", 0.75),
    # WI attorney bar numbers
    ("BAR_NUMBER", r"\bBar\s*#?\s*\d{5,6}\b", 0.85),
    # DHS case/matter IDs
    ("DHS_CASE_ID", r"\bDHS[-\s]?\d{6,10}\b", 0.85),
]


@lru_cache(maxsize=1)
def _engine() -> "AnalyzerEngine":
    if not _PRESIDIO_AVAILABLE:
        raise RuntimeError(
            "presidio-analyzer not installed. "
            "Run: pip install presidio-analyzer presidio-anonymizer spacy && "
            "python -m spacy download en_core_web_lg"
        )
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    # Add legal-domain recognizers
    extra_types = []
    for name, pattern_str, score in _LEGAL_PATTERNS_DEF:
        p = Pattern(name=name, regex=pattern_str, score=score)
        recognizer = PatternRecognizer(
            supported_entity=name,
            patterns=[p],
            supported_language="en",
        )
        registry.add_recognizer(recognizer)
        extra_types.append(name)
    _engine._extra_types = extra_types  # type: ignore[attr-defined]
    return AnalyzerEngine(registry=registry)


def _entity_types() -> list[str]:
    """Return entity types including any extras registered at engine init."""
    extras = getattr(_engine, "_extra_types", []) if _PRESIDIO_AVAILABLE else []
    return _ENTITY_TYPES + extras


def presidio_extract(text: str) -> list[tuple[str, str]]:
    """Drop-in replacement for enm._default_extract().

    Returns list of (entity_kind, entity_text) sorted longest-first,
    compatible with EntityMasker's extractor interface.
    """
    if not _PRESIDIO_AVAILABLE:
        # Graceful degradation: fall back to regex default
        from .enm import _default_extract
        return _default_extract(text)

    results = _engine().analyze(
        text=text,
        entities=_entity_types(),
        language="en",
    )
    # Sort longest-first (enm.py masking convention for overlap safety)
    results.sort(key=lambda r: r.end - r.start, reverse=True)
    return [(r.entity_type.lower(), text[r.start:r.end]) for r in results]


def make_presidio_masker():
    """Convenience factory: returns an EntityMasker using Presidio extraction."""
    from .enm import EntityMasker
    return EntityMasker(extractor=presidio_extract)
