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

    # AUDIT-FIX (P5 brief corrupts L5 custody): the synthesis body is *new*
    # content the brief itself authored — its content_inline legitimately
    # hashes to synthesis_hash, so inlining it is correct.
    synthesis_entry = {
        "observation_id": "obs-synthesis-0000",
        "source": "synthesis://body",
        "received_at": now,
        "content_hash": synthesis_hash,
        "content_inline": synthesis_b64,
        "custody_chain": [],
    }

    # AUDIT-FIX (P5): source witness entries previously had their content_inline
    # overwritten with the synthesis body while RETAINING the original
    # content_hash. The inlined bytes then no longer hashed to content_hash,
    # silently breaking chain-of-custody (best-evidence / replay would fail).
    # A brief does not re-host source bytes — it points at them. So each source
    # entry carries a content_ref to the original storage and an explicit
    # content_inline=None; the original content_hash is preserved untouched.
    #
    # The prior `[:5]` cap silently dropped sources beyond the fifth, omitting
    # them from the brief's custody chain. We preserve ALL source witnesses so
    # the brief faithfully cites every observation it derives from.
    source_entries = []
    for i, w in enumerate(refuted_attestation.get("witness", [])):
        orig_hash = w.get("content_hash")
        if orig_hash is None:
            # Cannot point at storage without a recorded hash; skip rather than
            # fabricate a hash/inline mismatch.
            continue
        # Prefer an existing pointer; otherwise reference the source observation
        # by its stable identity so verifiers can resolve the original bytes.
        content_ref = (
            w.get("content_ref")
            or f"attestation://observation/{w.get('observation_id', f'source-{i}')}"
        )
        source_entries.append({
            "observation_id": w.get("observation_id", f"obs-src-{i:04d}"),
            "source": w.get("source", f"attestation://source-{i}"),
            "received_at": w.get("received_at", now),
            "content_hash": orig_hash,
            "content_ref": content_ref,
            "content_inline": None,
            "custody_chain": w.get("custody_chain", []),
        })

    att["witness"] = [synthesis_entry] + source_entries

    return att
