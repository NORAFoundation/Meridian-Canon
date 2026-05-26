"""Dagster asset: RefutedAttestation → BriefAttestation."""
from __future__ import annotations

try:
    from dagster import asset
    _DAGSTER_AVAILABLE = True
except ImportError:
    _DAGSTER_AVAILABLE = False

    def asset(*args, **kwargs):  # type: ignore[misc]
        def decorator(fn):
            return fn
        return decorator if (args and callable(args[0])) else decorator


@asset(
    name="brief_attestation",
    group_name="canon_pipeline",
    description="Synthesize a BriefAttestation from a RefutedAttestation.",
)
def brief_attestation(context, refuted_attestation: dict) -> dict:
    """L5: Brief synthesis — produces BriefAttestation pre-seal.

    TODO: wire LM synthesis for production.
    Currently produces a structural brief stub.
    """
    import base64
    from datetime import datetime, timezone

    att = dict(refuted_attestation)
    att["kind"] = "brief"

    # Stub synthesis body
    synthesis_text = (
        f"Brief synthesis for: {att.get('subject', 'unknown subject')}\n\n"
        f"Derived from {len(att.get('witness', []))} observations. "
        f"Refutation: {len(att.get('refutation', {}).get('challenges', []))} challenges applied."
    )
    synthesis_bytes = synthesis_text.encode("utf-8")
    import hashlib
    synthesis_hash = "sha256:" + hashlib.sha256(synthesis_bytes).hexdigest()
    synthesis_b64 = base64.b64encode(synthesis_bytes).decode()

    now = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    att["witness"] = [
        {
            "observation_id": "obs-synthesis-0000",
            "source": "synthesis://body",
            "received_at": now,
            "content_hash": synthesis_hash,
            "content_inline": synthesis_b64,
            "custody_chain": [],
        }
    ] + [
        {
            "observation_id": f"obs-src-{i:04d}",
            "source": f"attestation://source-{i}",
            "received_at": now,
            "content_hash": w.get("content_hash", synthesis_hash),
            "content_inline": synthesis_b64,
            "custody_chain": [],
        }
        for i, w in enumerate(refuted_attestation.get("witness", [])[:5])
    ]

    return att
