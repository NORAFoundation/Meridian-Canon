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


def test_pae_matches_spec_known_good_vector():
    """AUDIT-FIX (K1): cross-language conformance fixture.

    These byte strings were computed BY HAND from the DSSE spec PAE rule:
        PAE = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    NOT by round-tripping our own implementation. Any conformant DSSE
    verifier in any language (Go in-toto, sigstore, etc.) must produce the
    same bytes for these inputs. If _pae regresses to a non-spec encoding,
    these literal assertions fail.
    """
    # Canonical DSSE spec example: type "http://example.com/HelloWorld",
    # payload b"hello world" (29-byte type, 11-byte payload).
    assert signing._pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )
    # Minimal hand-checkable vector: 1-byte type "a", 2-byte payload "bc".
    assert signing._pae("a", b"bc") == b"DSSEv1 1 a 2 bc"
    # Empty payload: still SP-separated, length 0, trailing SP then nothing.
    assert signing._pae("t", b"") == b"DSSEv1 1 t 0 "


def test_pae_is_not_legacy_nonconformant_encoding():
    """AUDIT-FIX (K1): guard against regression to the old broken format.

    The pre-fix encoding began with b"DSSEv1\\n" and used little-endian
    uint64 lengths. The spec encoding begins with b"DSSEv1 " (space) and
    uses ASCII-decimal lengths. Assert we are NOT emitting the legacy form.
    """
    out = signing._pae("text/plain", b"hello")
    assert out.startswith(b"DSSEv1 ")
    assert not out.startswith(b"DSSEv1\n")
    # No NUL bytes from little-endian uint64 length padding.
    assert b"\x00" not in out
