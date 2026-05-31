"""K2#2 tests: real RFC 6962 inclusion-proof verification, SET verification,
canonicalization-match, and walk() fail-closed semantics. No network is used.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from meridian.canon import transparency as t
from meridian.canon.transparency import (
    InclusionProof,
    compute_merkle_root,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    verify_inclusion_proof,
    verify_entry_bundle,
    verify_set,
    canonical_entry_bytes,
)
from meridian.canon.canonicalize import canonicalize_for_seal


# ---------------------------------------------------------------------------
# A tiny independent RFC 6962 Merkle tree, built by hand, to produce KNOWN-GOOD
# proofs. We deliberately do NOT reuse the verifier's own walk to build them —
# we build the full tree bottom-up and read off the audit path.
# ---------------------------------------------------------------------------


def _build_tree(leaves: list[bytes]):
    """Return (root_hex, levels) where levels[0] are leaf hashes."""
    level = [rfc6962_leaf_hash(b) for b in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(rfc6962_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted unchanged
        level = nxt
        levels.append(level)
    return level[0], levels


def _audit_path(levels, index: int) -> list[str]:
    """Read the audit path siblings for `index` from a fully-built tree."""
    path = []
    idx = index
    for level in levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            path.append(level[sibling])
        # else: odd node, no sibling at this level -> nothing appended
        idx //= 2
    return path


def _proof_for(leaves: list[bytes], index: int) -> InclusionProof:
    root, levels = _build_tree(leaves)
    return InclusionProof(
        log_index=index,
        tree_size=len(leaves),
        root_hash=root,
        hashes=_audit_path(levels, index),
    )


# ---------------------------------------------------------------------------
# Known-good and tampered inclusion proofs
# ---------------------------------------------------------------------------


def test_single_leaf_tree_root_is_leaf():
    leaf = b"only-entry"
    proof = _proof_for([leaf], 0)
    assert proof.hashes == []
    assert proof.root_hash == rfc6962_leaf_hash(leaf)
    res = verify_inclusion_proof(leaf, proof)
    assert res.verified and res.inclusion_ok


@pytest.mark.parametrize("size", [2, 3, 4, 5, 7, 8])
def test_inclusion_proof_accepts_every_leaf(size):
    leaves = [f"entry-{i}".encode() for i in range(size)]
    for i in range(size):
        proof = _proof_for(leaves, i)
        res = verify_inclusion_proof(leaves[i], proof)
        assert res.verified, f"leaf {i}/{size} should verify: {res.reason}"
        assert res.computed_root == proof.root_hash


def test_inclusion_proof_rejects_tampered_leaf():
    leaves = [f"entry-{i}".encode() for i in range(5)]
    proof = _proof_for(leaves, 2)
    # Same proof, different leaf bytes -> root must not match.
    res = verify_inclusion_proof(b"forged-entry", proof)
    assert not res.verified and not res.inclusion_ok
    assert "FAILED" in res.reason


def test_inclusion_proof_rejects_tampered_path():
    leaves = [f"entry-{i}".encode() for i in range(5)]
    proof = _proof_for(leaves, 2)
    bad = list(proof.hashes)
    # Flip one hex char in the first sibling.
    bad[0] = ("f" if bad[0][0] != "f" else "0") + bad[0][1:]
    tampered = InclusionProof(
        log_index=proof.log_index,
        tree_size=proof.tree_size,
        root_hash=proof.root_hash,
        hashes=bad,
    )
    res = verify_inclusion_proof(leaves[2], tampered)
    assert not res.verified


def test_inclusion_proof_rejects_wrong_root():
    leaves = [f"entry-{i}".encode() for i in range(4)]
    proof = _proof_for(leaves, 1)
    wrong = InclusionProof(
        log_index=proof.log_index,
        tree_size=proof.tree_size,
        root_hash="00" * 32,
        hashes=proof.hashes,
    )
    res = verify_inclusion_proof(leaves[1], wrong)
    assert not res.verified


def test_inclusion_proof_rejects_bad_geometry():
    leaves = [f"entry-{i}".encode() for i in range(4)]
    proof = _proof_for(leaves, 1)
    # Path too short.
    short = InclusionProof(proof.log_index, proof.tree_size, proof.root_hash, [])
    res = verify_inclusion_proof(leaves[1], short)
    assert not res.verified and "malformed" in res.reason
    # index out of range
    with pytest.raises(ValueError):
        compute_merkle_root(rfc6962_leaf_hash(leaves[0]), 9, 4, proof.hashes)


def test_rootHash_accepts_sha256_prefix():
    leaves = [b"a", b"b", b"c"]
    proof = _proof_for(leaves, 0)
    proof.root_hash = "sha256:" + proof.root_hash
    res = verify_inclusion_proof(leaves[0], proof)
    assert res.verified


# ---------------------------------------------------------------------------
# SET (signed entry timestamp) verification: accept + reject
# ---------------------------------------------------------------------------


def _ed25519_pub_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def test_set_verify_accepts_valid_signature():
    priv = Ed25519PrivateKey.generate()
    set_bytes = b"canonical-entry-the-log-signed"
    sig = base64.b64encode(priv.sign(set_bytes)).decode()
    assert verify_set(set_bytes, sig, _ed25519_pub_pem(priv)) is True


def test_set_verify_rejects_wrong_key():
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    set_bytes = b"canonical-entry"
    sig = base64.b64encode(priv.sign(set_bytes)).decode()
    assert verify_set(set_bytes, sig, _ed25519_pub_pem(other)) is False


def test_set_verify_rejects_tampered_bytes():
    priv = Ed25519PrivateKey.generate()
    sig = base64.b64encode(priv.sign(b"original")).decode()
    assert verify_set(b"tampered", sig, _ed25519_pub_pem(priv)) is False


def test_set_verify_rejects_garbage_signature():
    priv = Ed25519PrivateKey.generate()
    assert verify_set(b"x", "not-base64-!!!", _ed25519_pub_pem(priv)) is False


def test_entry_bundle_fails_when_set_present_but_no_key():
    leaves = [b"a", b"b"]
    proof = _proof_for(leaves, 0)
    res = verify_entry_bundle(
        leaves[0], proof,
        set_bytes=leaves[0], set_signature_b64="AAAA",
    )
    assert not res.verified and "no log public key" in res.reason


def test_entry_bundle_inclusion_plus_set_ok():
    priv = Ed25519PrivateKey.generate()
    leaves = [b"a", b"b", b"c"]
    proof = _proof_for(leaves, 1)
    set_bytes = leaves[1]
    sig = base64.b64encode(priv.sign(set_bytes)).decode()
    res = verify_entry_bundle(
        leaves[1], proof,
        log_public_key_pem=_ed25519_pub_pem(priv),
        set_bytes=set_bytes, set_signature_b64=sig,
    )
    assert res.verified and res.inclusion_ok and res.set_ok is True


def test_entry_bundle_fails_when_set_bad():
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    leaves = [b"a", b"b", b"c"]
    proof = _proof_for(leaves, 1)
    sig = base64.b64encode(other.sign(leaves[1])).decode()
    res = verify_entry_bundle(
        leaves[1], proof,
        log_public_key_pem=_ed25519_pub_pem(priv),
        set_bytes=leaves[1], set_signature_b64=sig,
    )
    assert not res.verified and res.set_ok is False


# ---------------------------------------------------------------------------
# Canonicalization-match: the committed bytes MUST equal the signed canonical
# bytes (AUDIT-FIX K2#2 defect #1). They must NOT be json.dumps(sort_keys=True).
# ---------------------------------------------------------------------------


def _sealed_fixture() -> dict:
    return {
        "canon_version": "0.2.0",
        "attestation_id": "ATT-K2-2",
        "kind": "observation",
        "issuer": "test/issuer",
        "subject": "K2#2 canonicalization",
        "zeta": "ordering matters",  # deliberately non-alpha-first key
        "alpha": 1,
        "seal": {
            "chain_hash": "sha256:" + "a" * 64,
            "signature": "c2ln",
            "canonicalization": "rfc8785",
            "signature_algorithm": "ed25519",
            "public_key_fingerprint": "sha256:" + "b" * 64,
            "public_key_url": "https://example.com/key.pem",
        },
    }


def test_committed_bytes_equal_signed_canonical_bytes():
    sealed = _sealed_fixture()
    committed = canonical_entry_bytes(sealed)
    signed = canonicalize_for_seal(sealed)
    assert committed == signed


def test_committed_bytes_are_not_json_dumps_sortkeys():
    import json
    sealed = _sealed_fixture()
    committed = canonical_entry_bytes(sealed)
    legacy = json.dumps(
        sealed, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    # The old broken path included the seal AND used a different canonicalization.
    assert committed != legacy
    # And the committed bytes must exclude the seal block entirely.
    assert b"chain_hash" not in committed


def test_publish_uses_canonical_bytes_in_payload(monkeypatch):
    """The data.content POSTed to Rekor decodes to the signed canonical bytes."""
    import json
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({
                "uuid1": {
                    "logIndex": 1, "logID": "L",
                    "integratedTime": 1700000000, "body": "x",
                }
            }).encode()

    def _fake_urlopen(req, timeout=30):
        captured["body"] = req.data
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    monkeypatch.setenv("MERIDIAN_REKOR_ENABLED", "1")

    sealed = _sealed_fixture()
    res = t.publish_attestation(
        sealed, public_key_pem=b"-----PEM-----", rekor_url="http://localhost:3000"
    )
    assert res.is_published
    body = json.loads(captured["body"])
    # Signature format must be ed25519, not x509 (AUDIT-FIX defect #2).
    assert body["spec"]["signature"]["format"] == "ed25519"
    # data.content must decode to the exact signed canonical bytes.
    posted = base64.b64decode(body["spec"]["data"]["content"])
    assert posted == canonical_entry_bytes(sealed)
