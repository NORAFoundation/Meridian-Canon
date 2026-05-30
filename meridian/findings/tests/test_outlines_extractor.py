"""Tests for OutlinesExtractor — graceful behavior without outlines installed."""
from meridian.findings.outlines_extractor import OutlinesExtractor, _OUTLINES_AVAILABLE
from meridian.findings.lm_extractor import LMOutput


class _MockGenerator:
    """Simulates an Outlines generator that returns valid LMOutput."""
    def __call__(self, prompt: str) -> LMOutput:
        return LMOutput(
            document_kind="court_filing",
            summary_one_sentence="Test document about a court hearing.",
            summary_paragraph="This is a test court filing document.",
        )


class _BrokenGenerator:
    """Simulates a generator that raises unexpectedly."""
    def __call__(self, prompt: str) -> LMOutput:
        raise RuntimeError("model crashed")


class _DictGenerator:
    def __call__(self, prompt):
        return {"document_kind": "correspondence", "summary_one_sentence": "A letter.", "summary_paragraph": ""}


def test_outlines_extractor_happy_path():
    extractor = OutlinesExtractor(_MockGenerator())
    result = extractor.extract("Some legal document text.")
    assert isinstance(result, LMOutput)
    assert result.document_kind == "court_filing"


def test_outlines_extractor_failure_is_loud_and_flagged():
    """AUDIT-FIX (P4a): a recognized generator failure returns a clearly-marked
    failure sentinel — confidence 0.0, extraction_failed flag — NOT an empty
    stub masquerading as a real result."""
    from meridian.findings.outlines_extractor import (
        EXTRACTION_FAILED_SENTINEL,
        is_failed_extraction,
    )
    extractor = OutlinesExtractor(_BrokenGenerator())
    result = extractor.extract("Some text that causes a crash.")
    assert isinstance(result, LMOutput)
    assert result.overall_confidence == 0.0
    assert "extraction_failed" in result.flags_for_human_review
    assert result.summary_one_sentence.startswith(EXTRACTION_FAILED_SENTINEL)
    assert is_failed_extraction(result)


def test_outlines_extractor_unrecognized_exception_propagates():
    """AUDIT-FIX (P4a): exceptions outside the recognized failure set (e.g.
    KeyboardInterrupt) must propagate, not be swallowed into a stub."""
    import pytest

    class _FatalGenerator:
        def __call__(self, prompt):
            raise KeyboardInterrupt()

    extractor = OutlinesExtractor(_FatalGenerator())
    with pytest.raises(KeyboardInterrupt):
        extractor.extract("text")


def test_outlines_extractor_truncation_flagged_and_confidence_capped():
    """AUDIT-FIX (P4d): input over 8000 chars is flagged and confidence capped
    at 0.5 so a dropped tail never silently vanishes."""
    class _HighConfGenerator:
        def __call__(self, prompt):
            return LMOutput(
                document_kind="court_filing",
                summary_one_sentence="x",
                summary_paragraph="y",
                overall_confidence=0.95,
            )

    extractor = OutlinesExtractor(_HighConfGenerator())
    short = extractor.extract("a" * 100)
    assert "input_truncated_at_8000_chars" not in short.flags_for_human_review
    assert short.overall_confidence == 0.95

    long = extractor.extract("a" * 9000)
    assert "input_truncated_at_8000_chars" in long.flags_for_human_review
    assert long.overall_confidence == 0.5


def test_outlines_extractor_dict_result():
    """Handles generator returning dict instead of LMOutput instance."""
    extractor = OutlinesExtractor(_DictGenerator())
    result = extractor.extract("Dear Sir,")
    assert isinstance(result, LMOutput)
    assert result.document_kind == "correspondence"


def test_outlines_available_flag():
    """_OUTLINES_AVAILABLE is a bool."""
    assert isinstance(_OUTLINES_AVAILABLE, bool)


def test_build_outlines_generator_no_outlines():
    """build_outlines_generator raises RuntimeError when outlines not installed."""
    if _OUTLINES_AVAILABLE:
        import pytest
        pytest.skip("outlines is installed")
    from meridian.findings.outlines_extractor import build_outlines_generator
    import pytest
    with pytest.raises(RuntimeError, match="outlines not installed"):
        build_outlines_generator("some/model")
