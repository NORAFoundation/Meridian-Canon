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


def test_outlines_extractor_never_raises():
    """Even when generator crashes, OutlinesExtractor returns a valid LMOutput."""
    extractor = OutlinesExtractor(_BrokenGenerator())
    result = extractor.extract("Some text that causes a crash.")
    assert isinstance(result, LMOutput)
    assert "extraction failed" in result.summary_one_sentence


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
