"""Section-aware document pre-chunking using Unstructured.io.

Unstructured partitions PDFs, emails, DOCX, HTML into typed elements
(Title, NarrativeText, Table, ListItem, etc.) BEFORE byte-level chunking.
This preserves section boundaries and produces semantically coherent chunks.

Install: pip install "unstructured[pdf,email]>=0.14"
         For scanned PDFs: pip install unstructured[pdf] + install poppler/tesseract

Usage:
    sections = partition_document(pdf_bytes, source_type="pdf")
    records = chunk_sections(sections, parent_sha256=..., custodian=...)
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

try:
    from unstructured.partition.auto import partition
    _UNSTRUCTURED_AVAILABLE = True
except ImportError:
    _UNSTRUCTURED_AVAILABLE = False

from .local_chunker import ChunkRecord, chunk_local, _now


@dataclass
class DocumentSection:
    """A typed, titled section from Unstructured partitioning."""
    section_title: Optional[str]
    element_type: str          # "Title", "NarrativeText", "Table", "ListItem", "Header", etc.
    text: str
    page_number: Optional[int] = None
    coordinates: Optional[dict] = None
    metadata: dict = field(default_factory=dict)

    @property
    def text_bytes(self) -> bytes:
        return self.text.encode("utf-8")


def partition_document(
    source: bytes | Path,
    *,
    source_type: str = "auto",
    strategy: str = "fast",
) -> list[DocumentSection]:
    """Partition a document into typed sections.

    Args:
        source: raw bytes or Path to file
        source_type: "pdf", "email", "docx", "html", "txt", "auto"
        strategy: "fast" (default) or "hi_res" (for scanned PDFs; requires OCR)

    Returns:
        List of DocumentSection, in document order.

    Falls back to a single section with full text if Unstructured not available.
    """
    if not _UNSTRUCTURED_AVAILABLE:
        # Graceful degradation: treat entire doc as one NarrativeText section
        if isinstance(source, Path):
            text = source.read_text(encoding="utf-8", errors="replace")
        else:
            text = source.decode("utf-8", errors="replace")
        return [DocumentSection(
            section_title=None,
            element_type="NarrativeText",
            text=text,
        )]

    kwargs: dict = {"strategy": strategy, "include_page_breaks": True}
    if isinstance(source, Path):
        kwargs["filename"] = str(source)
    else:
        import io
        kwargs["file"] = io.BytesIO(source)
        if source_type != "auto":
            kwargs["content_type"] = _source_type_to_mime(source_type)

    try:
        elements = partition(**kwargs)
    except Exception as e:
        # Partition failure → single fallback section
        raw = source.read_bytes() if isinstance(source, Path) else source
        return [DocumentSection(
            section_title=None,
            element_type="NarrativeText",
            text=raw.decode("utf-8", errors="replace"),
            metadata={"partition_error": str(e)},
        )]

    sections: list[DocumentSection] = []
    current_title: Optional[str] = None

    for el in elements:
        cat = getattr(el, "category", "NarrativeText")
        text = str(el).strip()
        if not text:
            continue
        if cat == "Title":
            current_title = text

        meta = {}
        if hasattr(el, "metadata"):
            m = el.metadata
            if hasattr(m, "page_number"):
                meta["page_number"] = m.page_number
            if hasattr(m, "filename"):
                meta["filename"] = m.filename

        sections.append(DocumentSection(
            section_title=current_title,
            element_type=cat,
            text=text,
            page_number=meta.get("page_number"),
            metadata=meta,
        ))

    return sections


def chunk_sections(
    sections: list[DocumentSection],
    *,
    parent_sha256: str,
    custodian: str,
    pii_tier: str = "internal",
    chunk_size: int = 4096,
) -> list[ChunkRecord]:
    """Hash and chunk each section via chunk_local(). Returns flat list of ChunkRecords."""
    records: list[ChunkRecord] = []
    for section in sections:
        section_bytes = section.text_bytes
        if not section_bytes:
            continue
        for record in chunk_local(
            section_bytes,
            parent_sha256=parent_sha256,
            custodian=custodian,
            pii_tier=pii_tier,
            chunk_size=chunk_size,
        ):
            records.append(record)
    return records


def partition_and_chunk(
    source: bytes | Path,
    *,
    parent_sha256: str,
    custodian: str,
    source_type: str = "auto",
    pii_tier: str = "internal",
    chunk_size: int = 4096,
    strategy: str = "fast",
) -> tuple[list[DocumentSection], list[ChunkRecord]]:
    """Convenience: partition then chunk in one call."""
    sections = partition_document(source, source_type=source_type, strategy=strategy)
    records = chunk_sections(
        sections,
        parent_sha256=parent_sha256,
        custodian=custodian,
        pii_tier=pii_tier,
        chunk_size=chunk_size,
    )
    return sections, records


def _source_type_to_mime(source_type: str) -> str:
    return {
        "pdf": "application/pdf",
        "email": "message/rfc822",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "html": "text/html",
        "txt": "text/plain",
    }.get(source_type, "application/octet-stream")
