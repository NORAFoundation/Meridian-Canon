"""Dagster job definitions for the Meridian-Canon pipeline."""
from __future__ import annotations

try:
    from dagster import define_asset_job, AssetSelection
    ingest_job = define_asset_job(
        "meridian_ingest_job",
        selection=AssetSelection.groups("canon_pipeline"),
        description="Full Canon pipeline: raw document → sealed attestation",
    )
except ImportError:
    ingest_job = None  # type: ignore[assignment]
