"""SearchAttestation builder tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from meridian.canon import emit, keys, signing
from meridian.query.attestation import build_search_attestation
from meridian.query.search import SearchResult


CUSTODIAN = "search-test"


@pytest.fixture
def published_keypair(tmp_path: Path) -> tuple[str, str]:
    private, public, fingerprint = keys.keygen(CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    pem_path = tmp_path / "search.pem"
    pem_path.write_bytes(pem)
    return fingerprint, f"file://{pem_path}"


def _sample_results() -> list[SearchResult]:
    return [
        SearchResult(
            chunk_id="11111111-1111-1111-1111-111111111111",
            document_id="22222222-2222-2222-2222-222222222222",
            text="This is the first relevant chunk.",
            matter_id="33333333-3333-3333-3333-333333333333",
            fused_score=0.0317,
            rerank_score=0.92,
            bm25_rank=2,
            dense_rank=1,
        ),
        SearchResult(
            chunk_id="44444444-4444-4444-4444-444444444444",
            document_id="55555555-5555-5555-5555-555555555555",
            text="A second result.",
            matter_id="33333333-3333-3333-3333-333333333333",
            fused_score=0.0298,
            rerank_score=0.74,
            bm25_rank=4,
            dense_rank=3,
        ),
    ]


def test_search_attestation_seals_and_walks(published_keypair: tuple[str, str]) -> None:
    """A SearchAttestation produced from typical results must seal and walk valid."""
    fingerprint, url = published_keypair
    att = build_search_attestation(
        query="deposition scheduling",
        results=_sample_results(),
        issuer="search-issuer",
        matter_id="33333333-3333-3333-3333-333333333333",
        custodian=CUSTODIAN,
        embedding_model="BAAI/bge-large-en-v1.5",
        reranker_used=True,
    )
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["kind"] == "search"
    assert sealed["seal"]["chain_hash"].startswith("sha256:")

    # The query bytes are inlined; verify content_hash matches the query.
    import base64, hashlib
    query_w = next(w for w in sealed["witness"] if w["source"].startswith("query://"))
    raw = base64.b64decode(query_w["content_inline"])
    assert raw == b"deposition scheduling"
    assert query_w["content_hash"] == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_search_attestation_supports_closure() -> None:
    """Every claim's supports must resolve. R3 closure check."""
    att = build_search_attestation(
        query="test query",
        results=_sample_results(),
        issuer="t",
        matter_id=None,
        custodian=CUSTODIAN,
    )
    obs_ids = {w["observation_id"] for w in att["witness"]}
    for c in att["findings"]["claims"]:
        for s in c["supports"]:
            assert s in obs_ids, f"unresolved support {s}"


def test_search_attestation_records_method() -> None:
    att = build_search_attestation(
        query="x", results=_sample_results(), issuer="t", matter_id=None,
        custodian=CUSTODIAN, embedding_model="bge-test", reranker_used=False,
    )
    assert "bge-test" in att["findings"]["method"]
    assert "RRF" in att["findings"]["method"]
    assert "Cross-encoder" not in att["findings"]["method"]


def test_search_attestation_with_reranker_records_it() -> None:
    att = build_search_attestation(
        query="x", results=_sample_results(), issuer="t", matter_id=None,
        custodian=CUSTODIAN, reranker_used=True,
    )
    assert "Cross-encoder re-rank applied" in att["findings"]["method"]


def test_replay_is_declined_not_asserted_survived() -> None:
    """AUDIT-FIX (MED-5): replay must NOT be applied with outcome=survived
    (the approximate HNSW index cannot guarantee exact replay). It must be
    declined with a machine-readable reason instead."""
    att = build_search_attestation(
        query="x", results=_sample_results(), issuer="t", matter_id=None,
        custodian=CUSTODIAN,
    )
    refutation = att["refutation"]
    # No replay challenge is asserted as applied.
    applied_types = {c["type"] for c in refutation["challenges"]}
    assert "replay" not in applied_types
    assert "replay" not in refutation["coverage"]["applied"]
    # Replay is declined with the determinism-limitation reason.
    declined = {d["type"]: d["reason"] for d in refutation["coverage"]["declined"]}
    assert "replay" in declined
    assert declined["replay"] == "approximate-index-does-not-guarantee-exact-replay"


def test_applied_consistency_check_outcome_is_real() -> None:
    """The single applied challenge is a consistency_check whose outcome
    reflects an actually-checkable property (unique chunk identities)."""
    att = build_search_attestation(
        query="x", results=_sample_results(), issuer="t", matter_id=None,
        custodian=CUSTODIAN,
    )
    challenges = att["refutation"]["challenges"]
    assert len(challenges) == 1
    ch = challenges[0]
    assert ch["type"] == "consistency_check"
    # _sample_results() has distinct chunk ids -> consistency survives.
    assert ch["outcome"] == "survived"


def test_search_attestation_with_med5_fix_still_seals_and_walks(
    published_keypair: tuple[str, str],
) -> None:
    """The MED-5 refutation rewrite must remain Canon-conformant (seals,
    and every challenge type is accounted for in coverage)."""
    fingerprint, url = published_keypair
    att = build_search_attestation(
        query="deposition scheduling",
        results=_sample_results(),
        issuer="search-issuer",
        matter_id="33333333-3333-3333-3333-333333333333",
        custodian=CUSTODIAN,
    )
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["kind"] == "search"
    # All five canon challenge types are either applied or declined.
    cov = sealed["refutation"]["coverage"]
    accounted = set(cov["applied"]) | {d["type"] for d in cov["declined"]}
    assert accounted == {
        "replay", "adversarial_prompt", "consistency_check",
        "coverage_audit", "counter_evidence",
    }


def test_empty_results_seals_safely(published_keypair: tuple[str, str]) -> None:
    """A query that returned no results still produces a valid Attestation
    (it records the absence as a method-summary claim)."""
    fingerprint, url = published_keypair
    att = build_search_attestation(
        query="extremely unlikely query terms",
        results=[],
        issuer="t",
        matter_id=None,
        custodian=CUSTODIAN,
    )
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["kind"] == "search"
    assert len(sealed["findings"]["claims"]) >= 1   # at least the method claim
