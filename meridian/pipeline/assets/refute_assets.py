"""Dagster asset: EnrichmentAttestation → RefutedAttestation via harness."""
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
    name="refuted_attestation",
    group_name="canon_pipeline",
    description="Run five-challenge refutation harness on enriched attestation.",
)
def refuted_attestation(context, enrichment_attestation: dict, llm=None) -> dict:
    """L4: Refutation harness — builds Refutation block."""
    from meridian.refute.harness import run_harness
    attestation = dict(enrichment_attestation)
    adapters = llm.get_adapters() if (llm is not None and hasattr(llm, "get_adapters")) else []
    refutation = run_harness(
        attestation,
        models=adapters if adapters else None,
        langfuse_session_id=attestation.get("attestation_id"),
    )
    attestation["refutation"] = refutation
    return attestation
