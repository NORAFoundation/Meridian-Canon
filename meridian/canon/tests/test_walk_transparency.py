"""K2#2 walk() integration: require_transparency fail-closed, proof-present
accept, tampered-proof reject. No network is used.
"""
from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest

from meridian.canon import emit, keys, signing, walk
from meridian.canon import transparency as t
from meridian.canon.hashing import sha256_hex


CUSTODIAN = "k2-2-walk-2026"


def _add_inline_content(att: dict) -> dict:
    raw = b"Bytes observed for the K2#2 transparency walk tests."
    att["witness"][0]["content_hash"] = "sha256:" + sha256_hex(raw)
    att["witness"][0]["content_ref"] = None
    att["witness"][0]["content_inline"] = base64.b64encode(raw).decode("ascii")
    return att


@pytest.fixture
def sealed_with_key(sample_attestation_dict, tmp_path: Path):
    _, public, fp = keys.keygen(CUSTODIAN)
    url = f"file://{tmp_path / 'k.pem'}"
    (tmp_path / "k.pem").write_bytes(signing.public_key_to_pem(public))
    att = _add_inline_content(copy.deepcopy(sample_attestation_dict))
    sealed = emit.emit(att, custodian=CUSTODIAN, public_key_url=url, fingerprint=fp)
    return sealed, fp


def _attach_proof(sealed: dict, *, tamper_leaf: bool = False) -> dict:
    """Build a real single-leaf inclusion proof over the attestation's canonical
    bytes and attach it under a `transparency` block (Meridian convention)."""
    sealed = copy.deepcopy(sealed)
    entry_bytes = t.canonical_entry_bytes(sealed)
    if tamper_leaf:
        entry_bytes = entry_bytes + b"X"  # proof will commit to wrong bytes
    leaf = t.rfc6962_leaf_hash(entry_bytes)
    # Proof is post-seal metadata: store under seal.transparency so it is
    # excluded from the chain_hash (the seal block is excluded wholesale).
    sealed["seal"]["transparency"] = {
        "rekor": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "rootHash": leaf,   # single-leaf tree: root == leaf hash
                "hashes": [],
            }
        }
    }
    return sealed


def test_attaching_proof_does_not_break_chain_hash(sealed_with_key):
    """The proof lives under seal.transparency (excluded from chain_hash), so
    step 3 (chain_hash recompute) must still pass after attaching it."""
    sealed, _ = sealed_with_key
    with_proof = _attach_proof(sealed)
    result = walk.walk(with_proof, require_transparency=True)
    assert result["steps"]["step3_chain_hash_recompute"] == "pass"


def test_disabled_default_notes_not_checked(sealed_with_key):
    sealed, _ = sealed_with_key
    result = walk.walk(sealed)
    assert result["verdict"] == "valid"
    assert result["transparency_basis"] == "not-checked"
    assert result["steps"]["step8_transparency"].startswith("not_checked")


def test_require_transparency_fails_closed_when_absent(sealed_with_key):
    sealed, _ = sealed_with_key
    result = walk.walk(sealed, require_transparency=True)
    assert result["verdict"] == "invalid"
    assert result["transparency_basis"] == "required-absent"
    assert "required but absent" in result["steps"]["step8_transparency"]


def test_require_transparency_passes_with_valid_proof(sealed_with_key):
    sealed, _ = sealed_with_key
    with_proof = _attach_proof(sealed)
    result = walk.walk(with_proof, require_transparency=True)
    assert result["verdict"] == "valid", result["steps"]
    assert result["transparency_basis"] == "verified"
    assert result["steps"]["step8_transparency"].startswith("pass")


def test_valid_proof_checked_even_when_not_required(sealed_with_key):
    """When a proof IS present, it is verified informationally even if not
    required; a present-and-valid proof reports 'verified'."""
    sealed, _ = sealed_with_key
    with_proof = _attach_proof(sealed)
    result = walk.walk(with_proof, require_transparency=False)
    assert result["verdict"] == "valid"
    assert result["transparency_basis"] == "verified"


def test_tampered_proof_fails_validity(sealed_with_key):
    """A proof committing to bytes that differ from the attestation's canonical
    bytes must FAIL inclusion and drop the verdict to invalid."""
    sealed, _ = sealed_with_key
    bad = _attach_proof(sealed, tamper_leaf=True)
    result = walk.walk(bad, require_transparency=True)
    assert result["verdict"] == "invalid"
    assert result["transparency_basis"] == "failed"
    assert "inclusion check failed" in result["steps"]["step8_transparency"]


def test_tampered_proof_fails_even_when_not_required(sealed_with_key):
    """Defense in depth: a present-but-bad proof fails the verdict regardless of
    the require_transparency flag — a planted bogus proof must not pass."""
    sealed, _ = sealed_with_key
    bad = _attach_proof(sealed, tamper_leaf=True)
    result = walk.walk(bad, require_transparency=False)
    assert result["verdict"] == "invalid"
    assert result["transparency_basis"] == "failed"


def test_transparency_preserves_trust_anchor(sealed_with_key):
    """K2#2 must not regress K2#1: pinning + transparency compose."""
    sealed, fp = sealed_with_key
    with_proof = _attach_proof(sealed)
    result = walk.walk(with_proof, trust_anchor=fp, require_transparency=True)
    assert result["verdict"] == "valid", result["steps"]
    assert result["trust_basis"] == "pinned"
    assert result["transparency_basis"] == "verified"
    assert "trust_warning" not in result


# --- DSSE path -------------------------------------------------------------


def _dsse_obs_with_real_hash() -> dict:
    from meridian.canon.tests.test_dsse import _minimal_obs
    att = _minimal_obs()
    raw = base64.b64decode(att["witness"][0]["content_inline"])
    att["witness"][0]["content_hash"] = "sha256:" + sha256_hex(raw)
    return att


def test_dsse_require_transparency_fails_closed(tmp_path: Path):
    _, pub, fp = keys.keygen("dsse-k2-2-absent")
    url = f"file://{tmp_path / 'k.pem'}"
    (tmp_path / "k.pem").write_bytes(signing.public_key_to_pem(pub))
    att = _dsse_obs_with_real_hash()
    env = emit.emit_dsse(att, custodian="dsse-k2-2-absent", public_key_url=url, fingerprint=fp)
    result = walk.walk(env, require_transparency=True)
    assert result["verdict"] == "invalid"
    assert result["transparency_basis"] == "required-absent"


def test_dsse_transparency_passes_with_proof_on_envelope(tmp_path: Path):
    _, pub, fp = keys.keygen("dsse-k2-2-proof")
    url = f"file://{tmp_path / 'k.pem'}"
    (tmp_path / "k.pem").write_bytes(signing.public_key_to_pem(pub))
    att = _dsse_obs_with_real_hash()
    env = emit.emit_dsse(att, custodian="dsse-k2-2-proof", public_key_url=url, fingerprint=fp)

    # The committed bytes are the INNER attestation's canonical bytes = payload.
    payload_bytes = base64.b64decode(env["payload"])
    leaf = t.rfc6962_leaf_hash(payload_bytes)
    env = copy.deepcopy(env)
    env["transparency"] = {
        "rekor": {"inclusionProof": {
            "logIndex": 0, "treeSize": 1, "rootHash": leaf, "hashes": [],
        }}
    }
    result = walk.walk(env, trust_anchor=fp, require_transparency=True)
    assert result["verdict"] == "valid", result["steps"]
    assert result["transparency_basis"] == "verified"
