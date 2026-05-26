"""Dagster asset: ObservationAttestation → EnrichmentAttestation via LM extraction."""
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
    name="enrichment_attestation",
    group_name="canon_pipeline",
    description="Run LM extraction on observations to produce typed EnrichmentAttestation.",
)
def enrichment_attestation(context, observation_attestation: dict) -> dict:
    """L3: LM-based enrichment with Outlines-constrained extraction.

    TODO: wire OutlinesExtractor or cloud LM path for production.
    Currently passes observation through with enrichment method stub.
    """
    enriched = dict(observation_attestation)
    enriched["kind"] = "enrichment"
    # Update method to indicate enrichment stage
    if "findings" in enriched:
        enriched["findings"] = dict(enriched["findings"])
        enriched["findings"]["method"] = "lm_extraction_pending"
    return enriched
