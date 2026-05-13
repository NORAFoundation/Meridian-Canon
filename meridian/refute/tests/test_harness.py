"""End-to-end harness tests: produces an R6-conformant Refutation block
across all dependency-presence combinations."""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest

from meridian.canon import emit, keys, signing
from meridian.canon.hashing import sha256_hex
from meridian.canon.schema import ChallengeOutcome
from meridian.refute import EchoAdapter, run_harness


CUSTODIAN = "harness-test"


def _enrichment_attestation(matter_id: str | None = None) -> dict:
    """Build an unsealed EnrichmentAttestation with three inferential claims."""
    raw = b"From: alice@example.com\nTo: bob@example.com\nSubject: Hearing on 2026-05-01\n\nLet's meet at 9am."
    inline = base64.b64encode(raw).decode("ascii")
    return {
        "kind": "enrichment",
        "issuer": "test-issuer",
        "matter_id": matter_id,
        "subject": "Test enrichment",
        "witness": [
            {
                "observation_id": "obs-EH-1",
                "source": "gmail://test/1",
                "received_at": "2026-04-18T14:22:30.100Z",
                "custody_chain": [],
                "content_hash": "sha256:" + sha256_hex(raw),
                "content_ref": None,
                "content_inline": inline,
            }
        ],
        "findings": {
            "method": "enrichment via test stub",
            "claims": [
                {
                    "claim_id": "claim-EH-1",
                    "statement": "Sender is alice@example.com.",
                    "supports": ["obs-EH-1"],
                    "inference_type": "deduction",
                    "gaps": ["DKIM not verified"],
                },
                {
                    "claim_id": "claim-EH-2",
                    "statement": "Hearing is 2026-05-01.",
                    "supports": ["obs-EH-1"],
                    "inference_type": "observation",
                    "gaps": [],
                },
                {
                    "claim_id": "claim-EH-3",
                    "statement": "Tone is collegial.",
                    "supports": ["obs-EH-1"],
                    "inference_type": "induction",
                    "gaps": ["subjective tone assessment"],
                },
            ],
        },
    }


def test_no_dependencies_yields_r6_conformant_block() -> None:
    """Even with zero LMs/registry/search, harness must produce a valid
    Refutation block per R6 (challenges non-empty + coverage with declines)."""
    att = _enrichment_attestation()
    block = run_harness(att)
    assert block["challenges"], "R6: at least one Challenge required"
    declined_types = {d["type"] for d in block["coverage"]["declined"]}
    # All five challenge types must be either applied or declined.
    expected = {"adversarial_prompt", "consistency_check", "coverage_audit",
                "counter_evidence", "replay"}
    accounted = set(block["coverage"]["applied"]) | declined_types
    assert expected <= accounted, f"unaccounted-for: {expected - accounted}"


def test_three_models_apply_adversarial_per_inferential_claim() -> None:
    att = _enrichment_attestation()
    m1 = EchoAdapter(name="m1", family="llama", outcome=ChallengeOutcome.SURVIVED)
    m2 = EchoAdapter(name="m2", family="mistral", outcome=ChallengeOutcome.SURVIVED)
    m3 = EchoAdapter(name="m3", family="gemma", outcome=ChallengeOutcome.SURVIVED)

    block = run_harness(att, models=[m1, m2, m3])
    advr = [c for c in block["challenges"] if c["type"] == "adversarial_prompt"]
    # Two inferential claims (deduction + induction); observation excluded.
    assert len(advr) == 2
    for ch in advr:
        assert "model_outcomes" in ch
        assert ch["consensus_outcome"] == "survived"


def test_contested_outcome_propagates_gap() -> None:
    att = _enrichment_attestation()
    m1 = EchoAdapter(name="m1", outcome=ChallengeOutcome.SURVIVED)
    m2 = EchoAdapter(name="m2", outcome=ChallengeOutcome.FAILED)
    m3 = EchoAdapter(name="m3", outcome=ChallengeOutcome.REVISED)
    block = run_harness(att, models=[m1, m2, m3])
    contested_chs = [c for c in block["challenges"] if c.get("consensus_outcome") == "contested"]
    assert contested_chs, "expected at least one contested challenge"
    # Claim gaps should include the disagreement record.
    target_id = contested_chs[0]["targets"][0]
    target_claim = next(c for c in att["findings"]["claims"] if c["claim_id"] == target_id)
    assert any("tri_model_disagreement" in g for g in target_claim["gaps"])


def test_consistency_check_with_registry() -> None:
    att = _enrichment_attestation()
    seen_entities: list[str] = []

    def lookup(entity: str) -> list[dict]:
        seen_entities.append(entity)
        if entity == "alice@example.com":
            return [{"claim_id": "claim-OLD", "statement": "Sender is alice@example.com.",
                     "attestation_id": "att-OLD"}]
        return []

    block = run_harness(att, registry_lookup=lookup)
    cons = [c for c in block["challenges"] if c["type"] == "consistency_check"]
    assert cons, "expected at least one consistency challenge"
    assert "alice@example.com" in seen_entities


def test_counter_evidence_with_search() -> None:
    att = _enrichment_attestation()

    def search(query: str, k: int) -> list[dict]:
        # The default negate() turns "Sender is alice..." into "Sender is not alice..."
        if "is not" in query.lower() and "alice" in query.lower():
            return [{"doc_id": "opposing-doc-1", "score": 0.85, "excerpt": "Different sender."}]
        return []

    block = run_harness(att, search=search)
    ctrev = [c for c in block["challenges"] if c["type"] == "counter_evidence"]
    assert ctrev
    revised = [c for c in ctrev if c["outcome"] == "revised"]
    assert revised, "expected counter-evidence to revise at least one claim"


def test_observation_only_attestation_emits_metadata_replay() -> None:
    """ObservationAttestations have no inferential claims; harness still
    produces an R6-conformant block with a metadata replay + four declines."""
    att = {
        "kind": "observation",
        "issuer": "test",
        "subject": "Observation only",
        "witness": [{
            "observation_id": "obs-X",
            "source": "test://x",
            "received_at": "2026-05-01T00:00:00.000000Z",
            "custody_chain": [],
            "content_hash": "sha256:" + "0" * 64,
            "content_ref": None,
            "content_inline": base64.b64encode(b"test").decode("ascii"),
        }],
        "findings": {
            "method": "raw observation",
            "claims": [{
                "claim_id": "claim-X",
                "statement": "bytes observed",
                "supports": ["obs-X"],
                "inference_type": "observation",
                "gaps": [],
            }],
        },
    }
    m1 = EchoAdapter(name="m1")
    block = run_harness(att, models=[m1, EchoAdapter(name="m2"), EchoAdapter(name="m3")])
    assert block["challenges"]
    declined_types = {d["type"] for d in block["coverage"]["declined"]}
    assert {"adversarial_prompt", "consistency_check", "counter_evidence"} <= declined_types
    # Reasons should be machine-readable.
    for d in block["coverage"]["declined"]:
        assert d["reason"], "every decline must carry a reason"


def test_harness_output_can_be_sealed(tmp_path: Any) -> None:
    """The Refutation block produced by run_harness must satisfy R6 strictly
    enough to pass through the Pydantic validator and be sealed."""
    private, public, fingerprint = keys.keygen(CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    pem_path = tmp_path / "h.pem"
    pem_path.write_bytes(pem)
    url = f"file://{pem_path}"

    att = _enrichment_attestation()
    block = run_harness(
        att,
        models=[EchoAdapter(name="m1"), EchoAdapter(name="m2"), EchoAdapter(name="m3")],
    )
    att["refutation"] = block

    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["seal"]["chain_hash"].startswith("sha256:")
