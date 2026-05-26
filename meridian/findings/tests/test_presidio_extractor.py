"""Tests for presidio_extractor — graceful degradation when Presidio not installed."""
from meridian.findings.presidio_extractor import presidio_extract, make_presidio_masker, _PRESIDIO_AVAILABLE


def test_presidio_extract_returns_list():
    """presidio_extract always returns a list (may fall back to regex)."""
    result = presidio_extract("Contact John Smith at john@example.com or 612-555-1234.")
    assert isinstance(result, list)
    # Each element is (kind_str, entity_str)
    for kind, text in result:
        assert isinstance(kind, str)
        assert isinstance(text, str)


def test_presidio_masker_roundtrip():
    """EntityMasker with Presidio extractor masks and unmasks correctly."""
    masker = make_presidio_masker()
    text = "Call Jane Doe at 612-555-0199 regarding case YYYYJC000001."
    masked, emap = masker.mask(text)
    unmasked = masker.unmask(masked, emap)
    assert unmasked == text
    # At minimum the regex fallback catches something (phone or name)
    assert len(emap) >= 1


def test_presidio_masker_is_entity_dependent():
    """is_entity_dependent returns True when statement contains S_n tokens."""
    masker = make_presidio_masker()
    text = "John Smith filed at court."
    masked, emap = masker.mask(text)
    if len(emap) > 0:
        first_token = next(iter(emap.token_to_original))
        assert masker.is_entity_dependent(first_token, emap)
    assert not masker.is_entity_dependent("no tokens here", emap)


def test_presidio_available_flag():
    """_PRESIDIO_AVAILABLE is a bool."""
    assert isinstance(_PRESIDIO_AVAILABLE, bool)
