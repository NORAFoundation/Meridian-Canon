"""Admissibility Auditor tests."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from meridian.canon import admissibility_auditor, emit, keys, signing, walk
from meridian.canon.hashing import sha256_hex


CUSTODIAN = "auditor-test"


@pytest.fixture
def published_keypair(tmp_path: Path) -> tuple[str, str]:
    """Generate a keypair and return (fingerprint, file:// URL)."""
    private, public, fingerprint = keys.keygen(CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    url_path = tmp_path / "auditor.pem"
    url_path.write_bytes(pem)
    return fingerprint, f"file://{url_path}"


@pytest.fixture
def sealed_target(sample_attestation_dict: dict, published_keypair: tuple[str, str]) -> dict:
    """A sealed target Attestation suitable for auditing."""
    fingerprint, url = published_keypair
    target = copy.deepcopy(sample_attestation_dict)
    raw = b"target evidence bytes"
    target["witness"][0]["content_hash"] = "sha256:" + sha256_hex(raw)
    target["witness"][0]["content_ref"] = None
    target["witness"][0]["content_inline"] = base64.b64encode(raw).decode("ascii")
    return emit.emit(target, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)


def test_audit_produces_valid_attestation(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    fingerprint, url = published_keypair
    audit_att = admissibility_auditor.audit(
        sealed_target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    assert audit_att["kind"] == "audit"
    # The audit attestation must itself be Canon-valid (R1-R7).
    result = walk.walk(audit_att)
    assert result["verdict"] == "valid", result


def test_audit_three_sections_present(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    fingerprint, url = published_keypair
    audit_att = admissibility_auditor.audit(
        sealed_target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    claim_ids = [c["claim_id"] for c in audit_att["findings"]["claims"]]
    # Section markers: AUTH (authentication), REL (reliability), CAV (caveats).
    assert any("AUTH" in cid for cid in claim_ids), "no Authentication record claims"
    assert any("REL" in cid for cid in claim_ids), "no Reliability factor claims"
    assert any("CAV" in cid for cid in claim_ids), "no Caveat claims"


def test_audit_does_not_declare_admissibility(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    """The audit must never use the word 'admissible' as a verdict."""
    fingerprint, url = published_keypair
    audit_att = admissibility_auditor.audit(
        sealed_target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    method = audit_att["findings"]["method"]
    assert "does not declare admissibility" in method.lower()


def test_audit_inherits_matter_id(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    fingerprint, url = published_keypair
    target = copy.deepcopy(sealed_target)
    target["matter_id"] = "12345678-1234-5678-1234-567812345678"
    audit_att = admissibility_auditor.audit(
        target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    assert audit_att["matter_id"] == "12345678-1234-5678-1234-567812345678"


def test_audit_targets_witness_references_target(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    """The audit's Witness must reference the target Attestation by id and chain_hash."""
    fingerprint, url = published_keypair
    audit_att = admissibility_auditor.audit(
        sealed_target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    target_id = sealed_target["attestation_id"]
    target_chain_hash = sealed_target["seal"]["chain_hash"]
    witness = audit_att["witness"][0]
    assert target_id in witness["observation_id"]
    assert witness["content_hash"] == target_chain_hash


def test_audit_detects_missing_challenge_coverage(
    sealed_target: dict, published_keypair: tuple[str, str]
) -> None:
    """If the target has incomplete coverage, the audit should call it out."""
    fingerprint, url = published_keypair
    target = copy.deepcopy(sealed_target)
    # Remove a declined entry so coverage is incomplete.
    target["refutation"]["coverage"]["declined"] = []
    target.pop("seal")
    target = emit.emit(target, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)

    audit_att = admissibility_auditor.audit(
        target,
        custodian=CUSTODIAN,
        public_key_url=url,
        fingerprint=fingerprint,
    )
    coverage_claim = next(
        c for c in audit_att["findings"]["claims"] if "REL-CV-" in c["claim_id"]
    )
    assert "neither applied nor declined" in " ".join(coverage_claim["gaps"])
