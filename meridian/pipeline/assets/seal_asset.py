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

    try:
        from meridian.canon.emit import emit
        custodian = getattr(canon, "custodian", "meridian-pipeline")
        public_key_url = getattr(canon, "public_key_url", "https://norafoundation.io/canon/key.pem")
        return emit(brief_attestation, custodian=custodian, public_key_url=public_key_url)
    except Exception as e:
        # Log error but don't fail the pipeline; return brief with error annotation
        brief_attestation["_seal_error"] = str(e)
        return brief_attestation
