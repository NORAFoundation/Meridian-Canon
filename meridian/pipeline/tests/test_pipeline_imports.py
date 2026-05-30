"""Tests that pipeline module imports cleanly with or without Dagster."""


class _FakeAdapter:
    """Minimal LMJsonAdapter: returns a schema-valid model with no real LM."""

    name = "fake-model"

    def complete_json(self, prompt, schema_model, *, max_tokens=1024, temperature=0.0):
        # Build a minimal valid instance for whatever extractor schema is asked.
        # All findings schemas require at most a document_kind + a summary field;
        # supply common required fields and let Pydantic defaults fill the rest.
        kwargs = {}
        fields = getattr(schema_model, "model_fields", {})
        for fname, finfo in fields.items():
            if finfo.is_required():
                if "summary" in fname:
                    kwargs[fname] = "stub summary"
                elif "kind" in fname:
                    kwargs[fname] = "other"
                else:
                    kwargs[fname] = "stub"
        return schema_model(**kwargs)


class _FakeLLM:
    """Stand-in for LLMResource exposing get_adapters()."""

    def get_adapters(self):
        return [_FakeAdapter()]


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
    """enrichment_attestation runs the real per-type extractor (AUDIT-FIX P3)."""
    import base64
    from meridian.pipeline.assets.enrich import enrichment_attestation

    body = b"This contract is between two parties regarding a payment of $5,000."
    obs = {
        "kind": "observation",
        "issuer": "test",
        "subject": "test://doc.txt",
        "witness": [{
            "observation_id": "obs-00",
            "source": "test://doc.txt",
            "content_hash": "sha256:" + "a" * 64,
            "content_inline": base64.b64encode(body).decode(),
        }],
        "findings": {"method": "direct", "claims": []},
        "refutation": {"challenges": [], "coverage": {"applied": [], "declined": []}},
    }
    result = enrichment_attestation(None, obs, llm=_FakeLLM())
    assert result["kind"] == "enrichment"
    # Real extraction ran: method names the runner/extractor and claims exist.
    assert "lm_extraction_pending" not in result["findings"]["method"]
    assert len(result["findings"]["claims"]) >= 1


def test_enrichment_requires_lm_adapter():
    """Without an LM adapter, enrich must FAIL rather than silently pass through."""
    import pytest
    from meridian.pipeline.assets.enrich import enrichment_attestation

    obs = {"kind": "observation", "subject": "test://doc", "witness": [], "findings": {}}
    with pytest.raises(RuntimeError):
        enrichment_attestation(None, obs, llm=None)


def test_seal_strict_propagates_failure():
    """AUDIT-FIX P1: under strict sealing, a signing failure must propagate
    (no unsigned attestation returned). With strict disabled, it degrades."""
    import pytest
    from meridian.pipeline.assets import seal_asset

    brief = {"kind": "brief", "subject": "test://x", "witness": []}

    class _Canon:
        custodian = "t"
        public_key_url = "https://example/key.pem"
        strict_sealing = True

    # Force emit() to fail by monkeypatching the import target.
    import meridian.canon.emit as emit_mod
    orig = emit_mod.emit

    def _boom(*a, **k):
        raise RuntimeError("no signing key")

    emit_mod.emit = _boom
    try:
        with pytest.raises(RuntimeError):
            seal_asset.sealed_attestation(None, brief, canon=_Canon())

        # Non-strict: degrades, annotates error, does not raise.
        class _CanonLax(_Canon):
            strict_sealing = False
        out = seal_asset.sealed_attestation(None, brief, canon=_CanonLax())
        assert out["_seal_error"]
    finally:
        emit_mod.emit = orig


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

    # L3: Enrich (real extractor via fake LM adapter)
    enriched = enrichment_attestation(None, obs, llm=_FakeLLM())
    assert enriched["kind"] == "enrichment"

    # L4: Refute (no LM adapters → observation-only harness)
    refuted = refuted_attestation(None, enriched, llm=None)
    assert "refutation" in refuted
    assert "challenges" in refuted["refutation"]


def test_brief_preserves_source_custody():
    """AUDIT-FIX P5: source witness entries must not get a content_inline that
    mismatches their content_hash. They point via content_ref instead, and the
    original hash is preserved; no `:5` cap drops sources."""
    import base64
    import hashlib
    from meridian.pipeline.assets.brief import brief_attestation

    # Build a refuted attestation with 7 source witnesses (more than the old cap)
    # each with a content_hash matching its OWN bytes.
    witnesses = []
    for i in range(7):
        b = f"source bytes {i}".encode()
        witnesses.append({
            "observation_id": f"obs-{i:04d}",
            "source": f"src://{i}",
            "content_hash": "sha256:" + hashlib.sha256(b).hexdigest(),
            "content_inline": base64.b64encode(b).decode(),
        })
    refuted = {
        "kind": "refuted",
        "subject": "test://brief",
        "witness": witnesses,
        "refutation": {"challenges": []},
    }

    brief = brief_attestation(None, refuted)
    assert brief["kind"] == "brief"

    # First entry is the synthesis body: its inline MUST hash to its content_hash.
    syn = brief["witness"][0]
    assert syn["source"] == "synthesis://body"
    digest = "sha256:" + hashlib.sha256(base64.b64decode(syn["content_inline"])).hexdigest()
    assert digest == syn["content_hash"]

    # All 7 sources preserved (no :5 cap), each carries content_ref + null inline,
    # and the original content_hash is untouched (custody intact).
    sources = brief["witness"][1:]
    assert len(sources) == 7
    for orig, entry in zip(witnesses, sources):
        assert entry["content_inline"] is None
        assert entry.get("content_ref")
        assert entry["content_hash"] == orig["content_hash"]


def test_ingest_idempotency_skips_existing():
    """AUDIT-FIX P2: a prior attestation over identical bytes short-circuits."""
    from meridian.pipeline.assets.ingest import observation_attestation

    doc = b"Idempotent doc.\n\nSection two."

    class _FakeCursor:
        def __init__(self, row):
            self._row = row
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, sql, params):
            self.last = (sql, params)
        def fetchone(self):
            return self._row

    class _FakeConn:
        def __init__(self, row):
            self._row = row
            self.closed = False
        def cursor(self):
            return _FakeCursor(self._row)
        def close(self):
            self.closed = True

    class _FakeDB:
        def __init__(self, row):
            self._row = row
        def get_connection(self):
            return _FakeConn(self._row)

    existing_payload = {"attestation_id": "EXISTING123", "kind": "observation"}
    # Tuple-row cursor returns (attestation_id, payload).
    db = _FakeDB(("EXISTING123", existing_payload))
    result = observation_attestation(
        None, document_bytes=doc, source_uri="test://x.txt",
        custodian="t", db=db,
    )
    assert result is existing_payload  # skipped rebuild, returned existing

    # No prior attestation → fresh build proceeds.
    db_empty = _FakeDB(None)
    fresh = observation_attestation(
        None, document_bytes=doc, source_uri="test://x.txt",
        custodian="t", db=db_empty,
    )
    assert fresh["kind"] == "observation"
    assert fresh["provenance"]["source_sha256"].startswith("sha256:")
