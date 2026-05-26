"""Local-First Chunking (paper §7.1).

Raw data is chunked, hashed, and bound on the custodian's machine before
any cloud transfer. Cloud-eligible payloads are restricted to non-raw
metadata (or encrypted-at-rest chunks if the custodian explicitly authorizes).

This module is intentionally cloud-agnostic: callers decide what goes to
cloud after chunks are produced. The `to_cloud_safe()` helper returns a
sanitized record suitable for cloud transmission.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional


@dataclass(frozen=True)
class ChunkRecord:
    """A locally-produced chunk with its content hash and metadata.

    `raw` holds the raw bytes; it is local-only by convention and is
    explicitly stripped by `to_cloud_safe()` before any cloud transfer.
    """

    chunk_id: str
    parent_sha256: str
    chunk_index: int
    chunk_offset: int
    chunk_size: int
    chunk_sha256: str
    custodian: str
    pii_tier: str
    chunked_at: str
    raw: bytes = field(repr=False, compare=False)

    def to_cloud_safe(self) -> dict[str, object]:
        """Return a dict safe to transmit to cloud compute (no raw bytes).

        Suitable for enqueuing into a remote enrichment job; the raw bytes
        must remain on the custodian's machine unless the PII tier and
        explicit custodian authorization permit cloud transmission.
        """
        d = asdict(self)
        d.pop("raw")
        return d


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def chunk_local(
    data: bytes,
    *,
    parent_sha256: str,
    custodian: str,
    pii_tier: str = "internal",
    chunk_size: int = 8192,
) -> Iterator[ChunkRecord]:
    """Split data into fixed-size chunks; hash each before yielding.

    For text-bearing formats with section structure (PDFs, emails), the
    higher-level worker should use a section-aware chunker upstream and
    then pass the section bytes here. This function is the primitive.

    Yields ChunkRecord per chunk, in order.
    """
    if not data:
        return
    n = len(data)
    idx = 0
    offset = 0
    while offset < n:
        end = min(offset + chunk_size, n)
        raw = data[offset:end]
        sha = _hash(raw)
        yield ChunkRecord(
            chunk_id=f"chunk-{parent_sha256[:8]}-{idx:06d}",
            parent_sha256=parent_sha256,
            chunk_index=idx,
            chunk_offset=offset,
            chunk_size=len(raw),
            chunk_sha256=sha,
            custodian=custodian,
            pii_tier=pii_tier,
            chunked_at=_now(),
            raw=raw,
        )
        idx += 1
        offset = end


def is_cloud_eligible(pii_tier: str) -> bool:
    """Return True if a chunk of this PII tier may be transmitted to cloud
    compute under default policy.

    Privileged and work-product material is foreclosed from cloud transmission
    by default (paper §6.5.1). The custodian may explicitly override per-batch.
    """
    return pii_tier in {"public", "low", "internal"}
