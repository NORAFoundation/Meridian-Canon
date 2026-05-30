"""Dagster asset: BriefAttestation → SealedAttestation."""
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
    name="sealed_attestation",
    group_name="canon_pipeline",
    description="Seal a BriefAttestation with Ed25519 signature and chain hash.",
)
def sealed_attestation(context, brief_attestation: dict, canon=None) -> dict:
    """L6: Emit sealed attestation.

    Requires canon resource to be configured with a valid custodian key.
    Returns the sealed attestation dict or the brief unchanged if no canon resource.
    """
    if canon is None:
        # No canon resource — return brief unsealed (for testing/dev)
        return brief_attestation

    from meridian.canon.emit import emit
    custodian = getattr(canon, "custodian", "meridian-pipeline")
    public_key_url = getattr(canon, "public_key_url", "https://norafoundation.io/canon/key.pem")
    strict = getattr(canon, "strict_sealing", True)

    # AUDIT-FIX (P1 seal swallows failures): never return an UNSIGNED attestation
    # downstream while pretending the run succeeded. Under strict sealing (the
    # default) any signing failure propagates so Dagster marks the run failed.
    # Graceful degradation is opt-in only via the canon resource's
    # strict_sealing=False, and even then the failure is annotated, not hidden.
    if strict:
        return emit(brief_attestation, custodian=custodian, public_key_url=public_key_url)

    try:
        return emit(brief_attestation, custodian=custodian, public_key_url=public_key_url)
    except Exception as e:
        if context is not None and hasattr(context, "log"):
            context.log.error("Sealing failed (strict_sealing disabled): %s", e)
        brief_attestation["_seal_error"] = str(e)
        return brief_attestation
