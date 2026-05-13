"""End-to-end emit + walk + tamper-detection tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from meridian.canon import emit, keys, signing, walk
from meridian.canon.canonicalize import canonicalize_for_seal
from meridian.canon.hashing import sha256_hex


CUSTODIAN = "test-custodian-2026"


@pytest.fixture
def published_keypair(tmp_path: Path) -> tuple[str, str]:
    """Generate a keypair and return (fingerprint, file:// URL to its PEM).

    The verifier uses urlopen() which supports file:// for tests.
    """
    private, public, fingerprint = keys.keygen(CUSTODIAN)
    pem = signing.public_key_to_pem(public)
    url_path = tmp_path / "published.pem"
    url_path.write_bytes(pem)
    return fingerprint, f"file://{url_path}"


def _add_inline_content(att: dict) -> dict:
    """Embed the witness content inline so the verifier can re-hash without network."""
    import base64
    raw = b"This is the observed bytes for tests."
    digest = "sha256:" + sha256_hex(raw)
    att["witness"][0]["content_hash"] = digest
    att["witness"][0]["content_ref"] = None
    att["witness"][0]["content_inline"] = base64.b64encode(raw).decode("ascii")
    return att


def test_emit_produces_walkable_attestation(
    sample_attestation_dict: dict, published_keypair: tuple[str, str]
) -> None:
    fingerprint, url = published_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)
    assert sealed["seal"]["chain_hash"].startswith("sha256:")

    result = walk.walk(sealed)
    assert result["verdict"] == "valid", result


def test_tamper_detection_signature(
    sample_attestation_dict: dict, published_keypair: tuple[str, str]
) -> None:
    """Mutate a single byte of the canonical form and confirm the verifier fails."""
    fingerprint, url = published_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)

    # Tamper: change the issuer string after sealing.
    tampered = copy.deepcopy(sealed)
    tampered["issuer"] = tampered["issuer"] + "-tampered"

    result = walk.walk(tampered)
    assert result["verdict"] == "invalid"
    assert "fail" in result["steps"]["step3_chain_hash_recompute"]


def test_tamper_detection_witness_content(
    sample_attestation_dict: dict, published_keypair: tuple[str, str]
) -> None:
    """If declared content_hash doesn't match the inlined bytes, step 4 fails."""
    fingerprint, url = published_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)

    # Tamper: replace the inline content with different bytes.
    import base64
    sealed["witness"][0]["content_inline"] = base64.b64encode(b"different").decode("ascii")
    # Re-seal so signature/chain_hash still verify (simulates upstream-fabrication scenario).
    sealed.pop("seal")
    re_sealed = emit.emit(sealed, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)

    result = walk.walk(re_sealed)
    # step4 should report failed > 0; overall verdict must be invalid.
    assert result["verdict"] == "invalid"
    assert result["steps"]["step4_witness_content_hashes"]["failed"] >= 1


def test_canonicalization_byte_identical_roundtrip(
    sample_attestation_dict: dict, published_keypair: tuple[str, str]
) -> None:
    fingerprint, url = published_keypair
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fingerprint)

    # Serialize and reparse; the recomputed chain_hash must match.
    s = json.dumps(sealed)
    parsed = json.loads(s)
    canonical = canonicalize_for_seal(parsed)
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == sealed["seal"]["chain_hash"]
