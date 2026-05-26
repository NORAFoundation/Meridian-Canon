"""Tests that pipeline module imports cleanly with or without Dagster."""


def test_pipeline_imports():
    """Pipeline module must import without error even without Dagster."""
    from meridian.pipeline import resources
    from meridian.pipeline.assets import ingest, enrich, refute_assets


def test_definitions_import():
    """Definitions import is None when Dagster not installed, or a Definitions object."""
    from meridian.pipeline.definitions import defs
    # defs is None when Dagster not installed; otherwise a Definitions object
    assert defs is None or hasattr(defs, "assets") or hasattr(defs, "get_all_asset_specs")


def test_observation_attestation_asset():
    """observation_attestation asset runs without Dagster context."""
    from meridian.pipeline.assets.ingest import observation_attestation
    result = observation_attestation(
        None,  # context — OK when Dagster not used
        document_bytes=b"Test document. Section 1.\n\nThis is paragraph one.\n\nSection 2.\n\nParagraph two.",
        source_uri="test://sample.txt",
        custodian="test-pipeline",
    )
    assert result["kind"] == "observation"
    assert len(result["witness"]) >= 1
    assert result["findings"]["claims"][0]["inference_type"] == "observation"


def test_enrichment_attestation_asset():
    """enrichment_attestation asset transforms observation to enrichment."""
    from meridian.pipeline.assets.enrich import enrichment_attestation

    obs = {
        "kind": "observation",
        "issuer": "test",
        "subject": "test://doc",
        "witness": [{"observation_id": "obs-00", "source": "test://", "content_hash": "sha256:" + "a" * 64}],
        "findings": {"method": "direct", "claims": []},
        "refutation": {"challenges": [], "coverage": {"applied": [], "declined": []}},
    }
    result = enrichment_attestation(None, obs)
    assert result["kind"] == "enrichment"
    assert result["findings"]["method"] == "lm_extraction_pending"


def test_full_pipeline_chain():
    """Full L0→L2 pipeline chain runs end-to-end without errors."""
    from meridian.pipeline.assets.ingest import observation_attestation
    from meridian.pipeline.assets.enrich import enrichment_attestation
    from meridian.pipeline.assets.refute_assets import refuted_attestation

    # L0→L2: Ingest
    obs = observation_attestation(
        None,
        document_bytes=b"Legal document text.\n\nSection 2 details.",
        source_uri="test://legal_doc.txt",
        custodian="test-pipeline",
    )
    assert obs["kind"] == "observation"

    # L3: Enrich
    enriched = enrichment_attestation(None, obs)
    assert enriched["kind"] == "enrichment"

    # L4: Refute (no LM adapters → observation-only harness)
    refuted = refuted_attestation(None, enriched, llm=None)
    assert "refutation" in refuted
    assert "challenges" in refuted["refutation"]
