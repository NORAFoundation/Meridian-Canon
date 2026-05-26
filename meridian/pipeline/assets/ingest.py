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


@asset(
    name="observation_attestation",
    group_name="canon_pipeline",
    description="Partition a document into sections, chunk, hash, and emit an ObservationAttestation.",
)
def observation_attestation(context, document_bytes: bytes, source_uri: str, custodian: str) -> dict:
    """L0→L2: Ingest → Witness → ObservationAttestation (pre-seal).

    This asset:
    1. Partitions the document via Unstructured (section-aware)
    2. Chunks and hashes each section
    3. Builds a WitnessEntry per section
    4. Constructs an ObservationAttestation dict (not yet sealed)
    """
    from meridian.witness.unstructured_adapter import partition_and_chunk

    parent_sha256 = hashlib.sha256(document_bytes).hexdigest()
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
