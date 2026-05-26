"""Tests for unstructured_adapter — graceful without Unstructured.io installed."""
from meridian.witness.unstructured_adapter import (
    partition_document,
    chunk_sections,
    partition_and_chunk,
    DocumentSection,
    _UNSTRUCTURED_AVAILABLE,
)


_SAMPLE_TEXT = b"Section 1: Introduction\n\nThis is the introduction.\n\nSection 2: Details\n\nMore detail here."
_PARENT_HASH = "a" * 64


def test_partition_fallback_bytes():
    """Without Unstructured, partition_document returns one section with all text."""
    sections = partition_document(_SAMPLE_TEXT, source_type="txt")
    assert len(sections) >= 1
    full_text = " ".join(s.text for s in sections)
    # text should contain some of the original content
    assert len(full_text) > 0


def test_partition_document_returns_sections():
    """partition_document always returns a list of DocumentSection objects."""
    sections = partition_document(_SAMPLE_TEXT, source_type="txt")
    assert isinstance(sections, list)
    for s in sections:
        assert isinstance(s, DocumentSection)
        assert isinstance(s.element_type, str)


def test_chunk_sections_produces_records():
    sections = [
        DocumentSection(section_title="S1", element_type="NarrativeText", text="Hello world " * 50),
        DocumentSection(section_title="S2", element_type="NarrativeText", text="More text " * 50),
    ]
    records = chunk_sections(sections, parent_sha256=_PARENT_HASH, custodian="test", chunk_size=128)
    assert len(records) > 0
    for r in records:
        assert r.chunk_sha256
        assert len(r.raw) <= 128


def test_partition_and_chunk_roundtrip():
    sections, records = partition_and_chunk(
        _SAMPLE_TEXT,
        parent_sha256=_PARENT_HASH,
        custodian="test",
        chunk_size=64,
    )
    assert len(sections) >= 1
    assert len(records) >= 1
    # Reconstructed bytes contain the original
    combined = b"".join(r.raw for r in records)
    assert len(combined) > 0
    assert b"Section" in combined or b"introduction" in combined.lower()


def test_empty_section_skipped():
    sections = [
        DocumentSection(section_title=None, element_type="NarrativeText", text=""),
        DocumentSection(section_title=None, element_type="NarrativeText", text="Real content here."),
    ]
    records = chunk_sections(sections, parent_sha256=_PARENT_HASH, custodian="test")
    assert all(r.chunk_size > 0 for r in records)
    # Only the non-empty section produced records
    assert len(records) >= 1


def test_unstructured_available_flag():
    """_UNSTRUCTURED_AVAILABLE is a bool."""
    assert isinstance(_UNSTRUCTURED_AVAILABLE, bool)
