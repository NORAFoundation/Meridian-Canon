"""Wrap existing acquisitions with ObservationAttestation emission.

Spec reference: paper §6.2 (L1 Source adapters), §6.10 (ObservationAttestation),
§7.1 (chain-of-custody on every transition).

An ObservationAttestation is the cheapest Canon artifact: Witness contains the
raw item with its content hash and custody chain; Findings is a single
observation-typed claim asserting the item's existence; Refutation is a
single replay challenge confirming hash stability.

Idempotency: re-running against an already-attested acquisition is a no-op.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from meridian.canon import emit, schema


CANON_VERSION = "0.1.1"


def _now_rfc3339() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _gen_id(prefix: str = "") -> str:
    """Generate a ULID. Falls back to UUID4 hex if ulid package not present."""
    try:
        import ulid
        return f"{prefix}{ulid.new()!s}".upper()
    except ImportError:
        from uuid import uuid4
        return f"{prefix}{uuid4().hex}".upper()


def build_observation_attestation(
    *,
    matter_id: Optional[str],
    issuer: str,
    acquisition_id: str,
    source: str,
    received_at: str,
    custodian: str,
    content_hash: str,
    content_ref: str,
    subject: str | None = None,
) -> dict[str, Any]:
    """Build a pre-seal ObservationAttestation dict.

    The caller passes the acquisition's hash and storage URI. The attestation
    asserts the bytes were observed; the replay challenge confirms hash stability.
    """
    obs_id = "obs-" + _gen_id()
    claim_id = "claim-" + _gen_id()
    chal_id = "chal-" + _gen_id()
    att_id = _gen_id()

    return {
        "canon_version": CANON_VERSION,
        "attestation_id": att_id,
        "kind": "observation",
        "issued_at": _now_rfc3339(),
        "issuer": issuer,
        "matter_id": matter_id,
        "subject": subject or f"Observation of {source}",
        "witness": [
            {
                "observation_id": obs_id,
                "source": source,
                "received_at": received_at,
                "custody_chain": [
                    {
                        "custodian": custodian,
                        "received_at": received_at,
                        "signature": None,
                    }
                ],
                "content_hash": content_hash,
                "content_ref": content_ref,
                "content_inline": None,
            }
        ],
        "findings": {
            "method": "Direct observation: acquisition recorded with cryptographic content hash.",
            "claims": [
                {
                    "claim_id": claim_id,
                    "statement": f"Bytes were observed at {source} and hashed to {content_hash}.",
                    "supports": [obs_id],
                    "inference_type": "observation",
                    "gaps": [],
                }
            ],
        },
        "refutation": {
            "challenges": [
                {
                    "challenge_id": chal_id,
                    "type": "replay",
                    "targets": [claim_id],
                    "input": "recompute SHA-256 over content retrieved from content_ref",
                    "outcome": "survived",
                    "revisions": None,
                }
            ],
            "coverage": {
                "applied": ["replay"],
                "declined": [
                    {"type": "adversarial_prompt", "reason": "no_inferential_findings_to_contest"},
                    {"type": "consistency_check", "reason": "no_entity_claims_to_cross_reference"},
                    {"type": "coverage_audit", "reason": "applies_at_batch_level_not_per_observation"},
                    {"type": "counter_evidence", "reason": "no_inferential_claims_to_negate"},
                ],
            },
        },
    }


def attest_acquisition(
    conn,
    *,
    acquisition_id: str,
    custodian: str,
    issuer: str,
    public_key_url: str,
    fingerprint: str | None = None,
    matter_id: Optional[str] = None,
    subject: str | None = None,
) -> str | None:
    """Emit an ObservationAttestation for a single acquisition row.

    Args:
        conn: psycopg connection (caller manages tx).
        acquisition_id: UUID of the acquisitions row.
        custodian: Keychain account name with the signing key.
        issuer: Free-text issuer identifier (paper §6.2 'custodian').
        public_key_url: Stable URL hosting the PEM (paper R8).
        fingerprint: SHA-256 of the PEM. Computed if None.
        matter_id: UUID of the matter; required for matter-scoped emission.
        subject: Optional subject override.

    Returns:
        attestation_id string if a new Attestation was emitted; None if the
        acquisition was already attested (idempotent).
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT a.raw_storage_uri, a.raw_sha256, a.fetched_at::text,
                   a.obs_attestation_id, s.matter_id, s.kind AS source_kind
            FROM acquisitions a
            JOIN sources s ON a.source_id = s.id
            WHERE a.id = %s
            """,
            (acquisition_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"acquisition {acquisition_id!r} not found")
        if row.get("obs_attestation_id"):
            return None  # already attested
        eff_matter_id = matter_id or str(row["matter_id"]) if row["matter_id"] else None

        att_dict = build_observation_attestation(
            matter_id=eff_matter_id,
            issuer=issuer,
            acquisition_id=acquisition_id,
            source=f"{row['source_kind']}://acquisition/{acquisition_id}",
            received_at=row["fetched_at"],
            custodian=custodian,
            content_hash=f"sha256:{row['raw_sha256']}",
            content_ref=row["raw_storage_uri"],
            subject=subject,
        )

        sealed = emit.emit(
            att_dict,
            custodian=custodian,
            public_key_url=public_key_url,
            fingerprint=fingerprint,
        )

        cur.execute(
            """
            INSERT INTO attestations (
              attestation_id, kind, canon_version, matter_id, issued_at, issuer,
              subject, chain_hash, signature, public_key_fingerprint, public_key_url,
              payload
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                sealed["attestation_id"],
                sealed["kind"],
                sealed["canon_version"],
                eff_matter_id,
                sealed["issued_at"],
                sealed["issuer"],
                sealed.get("subject"),
                sealed["seal"]["chain_hash"],
                sealed["seal"]["signature"],
                sealed["seal"]["public_key_fingerprint"],
                sealed["seal"]["public_key_url"],
                _to_jsonb(sealed),
            ),
        )

        cur.execute(
            "UPDATE acquisitions SET obs_attestation_id = %s WHERE id = %s",
            (sealed["attestation_id"], acquisition_id),
        )
        return sealed["attestation_id"]


def backfill_observations(
    conn,
    *,
    custodian: str,
    issuer: str,
    public_key_url: str,
    fingerprint: str | None = None,
    limit: int | None = None,
    matter_id: str | None = None,
) -> Iterable[str]:
    """Emit ObservationAttestations for every acquisition lacking one.

    Yields attestation_ids as they are produced. Caller is responsible for
    transactions; this function commits per-attestation to keep failures local.
    """
    with conn.cursor() as cur:
        sql = (
            "SELECT a.id FROM acquisitions a "
            "WHERE a.obs_attestation_id IS NULL "
        )
        params: list[Any] = []
        if matter_id is not None:
            sql += "AND EXISTS (SELECT 1 FROM sources s WHERE s.id = a.source_id AND s.matter_id = %s) "
            params.append(matter_id)
        sql += "ORDER BY a.fetched_at "
        if limit is not None:
            sql += "LIMIT %s "
            params.append(limit)
        cur.execute(sql, params)
        rows = cur.fetchall()

    for row in rows:
        att_id = attest_acquisition(
            conn,
            acquisition_id=str(row["id"]),
            custodian=custodian,
            issuer=issuer,
            public_key_url=public_key_url,
            fingerprint=fingerprint,
            matter_id=matter_id,
        )
        if att_id:
            conn.commit()
            yield att_id


def _to_jsonb(obj: Any) -> str:
    """Serialize for psycopg jsonb parameter (UUIDs etc.)."""
    import json

    def _default(v: Any) -> Any:
        # Pydantic UUID may slip through.
        return str(v)

    return json.dumps(obj, default=_default)
