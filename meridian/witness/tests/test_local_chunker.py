"""Local-First Chunking tests."""

from __future__ import annotations

import hashlib

from meridian.witness.local_chunker import ChunkRecord, chunk_local, is_cloud_eligible


def test_chunks_concatenate_to_input() -> None:
    data = b"a" * 20000 + b"b" * 5000
    chunks = list(chunk_local(data, parent_sha256="abc", custodian="me", chunk_size=8192))
    assert b"".join(c.raw for c in chunks) == data
    assert chunks[0].chunk_offset == 0
    assert chunks[-1].chunk_offset + chunks[-1].chunk_size == len(data)


def test_each_chunk_hash_matches_bytes() -> None:
    data = b"hello world"
    chunks = list(chunk_local(data, parent_sha256="x", custodian="me", chunk_size=4))
    for c in chunks:
        assert c.chunk_sha256 == hashlib.sha256(c.raw).hexdigest()


def test_to_cloud_safe_strips_raw() -> None:
    data = b"sensitive content"
    chunks = list(chunk_local(data, parent_sha256="x", custodian="me"))
    safe = chunks[0].to_cloud_safe()
    assert "raw" not in safe
    assert safe["chunk_sha256"] == chunks[0].chunk_sha256


def test_pii_eligibility() -> None:
    assert is_cloud_eligible("public")
    assert is_cloud_eligible("internal")
    assert not is_cloud_eligible("privileged")
    assert not is_cloud_eligible("work_product")
    assert not is_cloud_eligible("sensitive")


def test_empty_input_produces_no_chunks() -> None:
    assert list(chunk_local(b"", parent_sha256="x", custodian="me")) == []
