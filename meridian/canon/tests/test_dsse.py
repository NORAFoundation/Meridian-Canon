"""Tests for DSSE envelope emission and verification."""
from __future__ import annotations

import base64

from meridian.canon import keys, signing, emit
from meridian.canon.schema import DSSEEnvelope


def _minimal_obs():
    return {
        "kind": "observation",
        "issuer": "test-issuer",
        "subject": "test subject",
        "witness": [{
            "observation_id": "obs-test01",
            "source": "test://doc",
            "received_at": "2026-01-01T00:00:00.000000Z",
            "content_hash": "sha256:" + "a" * 64,
            "content_inline": base64.b64encode(b"hello world").decode(),
            "custody_chain": [],
        }],
        "findings": {
            "method": "direct observation",
            "claims": [{
                "claim_id": "claim-01",
                "statement": "document received",
                "supports": ["obs-test01"],
                "inference_type": "observation",
                "gaps": [],
            }],
        },
        "refutation": {
            "challenges": [{
                "challenge_id": "chal-01",
                "type": "replay",
                "targets": ["claim-01"],
                "input": "hash check",
                "outcome": "survived",
            }],
            "coverage": {"applied": ["replay"], "declined": []},
        },
    }


def test_emit_dsse_roundtrip():
    """emit_dsse produces a valid DSSEEnvelope; verify_dsse confirms the signature."""
    custodian = "test-dsse"
    private_key, public_key, fingerprint = keys.keygen(custodian)
    att = _minimal_obs()
    envelope = emit.emit_dsse(att, custodian=custodian, public_key_url="https://example.com/key.pem")

    # Structural validation
    DSSEEnvelope.model_validate(envelope)

    # Verify signature using the fingerprint from the keygen
    pub_pem = keys.load_public_pem(fingerprint)
    pub_key = signing.public_key_from_pem(pub_pem)
    payload_bytes = base64.b64decode(envelope["payload"])
    sig = envelope["signatures"][0]["sig"]
    assert signing.verify_dsse(pub_key, payload_bytes, sig)


def test_dsse_tamper_detected():
    """Altering the payload invalidates the DSSE signature."""
    custodian = "test-dsse-tamper"
    private_key, public_key, fingerprint = keys.keygen(custodian)
    att = _minimal_obs()
    envelope = emit.emit_dsse(att, custodian=custodian, public_key_url="https://example.com/key.pem")

    pub_pem = keys.load_public_pem(fingerprint)
    pub_key = signing.public_key_from_pem(pub_pem)

    # Tamper with payload
    tampered = base64.b64decode(envelope["payload"]) + b"X"
    sig = envelope["signatures"][0]["sig"]
    assert not signing.verify_dsse(pub_key, tampered, sig)


def test_dsse_envelope_has_chain_hash():
    """Emitted envelope includes a sha256: chain_hash."""
    custodian = "test-dsse-hash"
    keys.keygen(custodian)
    att = _minimal_obs()
    envelope = emit.emit_dsse(att, custodian=custodian, public_key_url="https://example.com/key.pem")
    assert envelope["chain_hash"].startswith("sha256:")
    assert len(envelope["chain_hash"]) == 71  # "sha256:" + 64 hex chars


def test_pae_deterministic():
    """_pae produces the same bytes for the same inputs."""
    p1 = signing._pae("text/plain", b"hello")
    p2 = signing._pae("text/plain", b"hello")
    assert p1 == p2


def test_pae_distinguishes_type_and_payload():
    """_pae output differs when payloadType or payload differs."""
    a = signing._pae("type/a", b"payload")
    b = signing._pae("type/b", b"payload")
    c = signing._pae("type/a", b"different")
    assert a != b
    assert a != c
