"""Dagster asset: raw document → ObservationAttestation."""
from __future__ import annotations
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional

try:
    from dagster import asset, Output, MetadataValue
    _DAGSTER_AVAILABLE = True
except ImportError:
    _DAGSTER_AVAILABLE = False

    def asset(*args, **kwargs):  # type: ignore[misc]
        def decorator(fn):
            return fn
        return decorator if (args and callable(args[0])) else decorator

    class Output:  # type: ignore[no-redef]
        def __init__(self, value, metadata=None):
            self.value = value

    class MetadataValue:  # type: ignore[no-redef]
        @staticmethod
        def text(s):
            return s

        @staticmethod
        def int(n):
            return n


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _find_existing_attestation(database, parent_sha256: str) -> Optional[dict]:
    """Return a previously-emitted attestation for these source bytes, or None.

    AUDIT-FIX (P2): idempotency probe. The source document SHA-256 is recorded
    in the attestation payload at ``provenance.source_sha256``. We look it up
    there. ``database`` may be None (no resource configured — e.g. local/dev or
    the no-DB test path), in which case dedup is skipped and a fresh build
    proceeds. Any DB error is surfaced, not swallowed, so a degraded DB cannot
    silently produce duplicate attestations.
    """
    if database is None:
        return None
    chain_hash_full = "sha256:" + parent_sha256
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            # Match either the denormalized chain_hash column (sealed identity
            # of an observation over these exact bytes) or the source sha256
            # recorded inside the payload provenance block.
            cur.execute(
                """
                SELECT attestation_id, payload
                FROM attestations
                WHERE kind = 'observation'
                  AND (chain_hash = %s
                       OR payload #>> '{provenance,source_sha256}' = %s)
                ORDER BY issued_at
                LIMIT 1
                """,
                (chain_hash_full, chain_hash_full),
            )
            row = cur.fetchone()
        if row is None:
            return None
        # Support both dict-row (row_factory) and tuple-row cursors.
        if isinstance(row, dict):
            payload = row.get("payload")
            if isinstance(payload, dict):
                return payload
            return {"attestation_id": row.get("attestation_id")}
        attestation_id, payload = row[0], row[1]
        if isinstance(payload, dict):
            return payload
        return {"attestation_id": attestation_id}
    finally:
        conn.close()


@asset(
    name="observation_attestation",
    group_name="canon_pipeline",
    description="Partition a document into sections, chunk, hash, and emit an ObservationAttestation.",
)
def observation_attestation(
    context,
    document_bytes: bytes,
    source_uri: str,
    custodian: str,
    db=None,
) -> dict:
    """L0→L2: Ingest → Witness → ObservationAttestation (pre-seal).

    This asset:
    1. Partitions the document via Unstructured (section-aware)
    2. Chunks and hashes each section
    3. Builds a WitnessEntry per section
    4. Constructs an ObservationAttestation dict (not yet sealed)

    Idempotency (AUDIT-FIX P2): the parent document SHA-256 is deterministic.
    Before building a fresh attestation, query existing attestations for one
    already emitted over the same source bytes (mirrors the
    ``obs_attestation_id`` no-op check in witness/wrapper.py:attest_acquisition).
    If found, return the existing attestation_id and skip re-emission so the
    pipeline does not produce duplicate, divergently-timestamped attestations
    for identical inputs.
    """
    from meridian.witness.unstructured_adapter import partition_and_chunk

    parent_sha256 = hashlib.sha256(document_bytes).hexdigest()

    # AUDIT-FIX (P2 no ingest idempotency): dedup by source sha256 before build.
    existing = _find_existing_attestation(db, parent_sha256)
    if existing is not None:
        if _DAGSTER_AVAILABLE and context is not None:
            context.add_output_metadata({
                "idempotent_skip": MetadataValue.text("true"),
                "existing_attestation_id": MetadataValue.text(str(existing.get("attestation_id", ""))),
                "parent_sha256": MetadataValue.text(parent_sha256[:16] + "..."),
            })
        return existing
    sections, records = partition_and_chunk(
        document_bytes,
        parent_sha256=parent_sha256,
        custodian=custodian,
        pii_tier="internal",
    )

    witness_entries = []
    for i, section in enumerate(sections):
        sec_bytes = section.text_bytes
        sec_hash = "sha256:" + hashlib.sha256(sec_bytes).hexdigest()
        obs_id = f"obs-{parent_sha256[:8]}-{i:04d}"
        witness_entries.append({
            "observation_id": obs_id,
            "source": f"{source_uri}#section-{i}",
            "received_at": _now_utc(),
            "content_hash": sec_hash,
            "content_inline": base64.b64encode(sec_bytes).decode(),
            "custody_chain": [{"custodian": custodian, "received_at": _now_utc()}],
        })

    claim_id = f"claim-{parent_sha256[:8]}-00"
    attestation = {
        "kind": "observation",
        "issuer": custodian,
        "subject": source_uri,
        # AUDIT-FIX (P2): persist the deterministic source hash so subsequent
        # runs over identical bytes resolve to this attestation and skip rebuild.
        "provenance": {"source_sha256": "sha256:" + parent_sha256},
        "witness": witness_entries,
        "findings": {
            "method": "direct observation via Unstructured.io partitioning",
            "claims": [{
                "claim_id": claim_id,
                "statement": f"Document received and hashed from {source_uri}",
                "supports": [w["observation_id"] for w in witness_entries],
                "inference_type": "observation",
                "gaps": [],
            }],
        },
        "refutation": {
            "challenges": [{
                "challenge_id": f"chal-{parent_sha256[:8]}-00",
                "type": "replay",
                "targets": [claim_id],
                "input": f"recompute SHA-256 over source bytes; expected sha256:{parent_sha256}",
                "outcome": "survived",
            }],
            "coverage": {
                "applied": ["replay"],
                "declined": [
                    {"type": "adversarial_prompt", "reason": "no_inference"},
                    {"type": "consistency_check", "reason": "no_entities"},
                    {"type": "counter_evidence", "reason": "no_inference"},
                    {"type": "coverage_audit", "reason": "batch_level"},
                ],
            },
        },
    }

    if _DAGSTER_AVAILABLE and context is not None:
        context.add_output_metadata({
            "witness_count": MetadataValue.int(len(witness_entries)),
            "source_uri": MetadataValue.text(source_uri),
            "parent_sha256": MetadataValue.text(parent_sha256[:16] + "..."),
        })

    return attestation
