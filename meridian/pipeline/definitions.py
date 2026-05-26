"""Dagster Definitions — entry point for the Meridian-Canon pipeline."""
from __future__ import annotations

try:
    from dagster import Definitions, load_assets_from_modules
    _DAGSTER_AVAILABLE = True
except ImportError:
    _DAGSTER_AVAILABLE = False

if _DAGSTER_AVAILABLE:
    from . import resources
    from .assets import ingest, enrich, refute_assets, brief, seal_asset

    _all_assets = load_assets_from_modules([ingest, enrich, refute_assets, brief, seal_asset])

    defs = Definitions(
        assets=_all_assets,
        resources={
            "db": resources.DatabaseResource(),
            "llm": resources.LLMResource(),
            "canon": resources.CanonResource(),
        },
    )
else:
    defs = None  # type: ignore[assignment]
