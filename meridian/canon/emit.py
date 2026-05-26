"""Build, canonicalize, hash, sign, persist a Canon-conformant Attestation.

Spec reference: paper §6.8 (L7 Emission), R7 (canonical sealing), R8 (key discoverability).

Usage:
    sealed = emit(attestation_dict, custodian="acme-corp-2026", public_key_url="https://...")
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from . import keys, signing
from .canonicalize import canonicalize_for_seal
from .hashing import chain_hash, public_key_fingerprint
from .schema import Attestation, Seal


def _now_rfc3339() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def emit(
    attestation_dict: dict[str, Any],
    *,
    custodian: str,
    public_key_url: str,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    """Take a partial Attestation dict (no seal), validate, sign, return sealed dict.

    The Attestation is validated against the Pydantic schema (R1) before sealing
    (which catches R3, R4, R5, R6 violations), then canonicalized via RFC 8785,
    chain-hashed via SHA-256, and signed with Ed25519.

    The Keychain entry for `custodian` must exist (call keys.keygen first).

    Returns the dict with seal populated. The caller is responsible for persistence.
    """
    # Set canonical header fields if not already present.
    attestation_dict.setdefault("canon_version", "0.1.1")
    attestation_dict.setdefault("issued_at", _now_rfc3339())
    if "attestation_id" not in attestation_dict:
        # ULID preferred per spec; uuid4 is the fallback.
        try:
            import ulid
            attestation_dict["attestation_id"] = str(ulid.new()).upper()
        except ImportError:
            attestation_dict["attestation_id"] = uuid4().hex.upper()

    # Validate structure (R1, R3, R4, R5, R6).
    Attestation.model_validate({**attestation_dict, "seal": None})

    # Load private key.
    private_key = keys.load_private(custodian)

    # Compute fingerprint if not supplied (must match the published public key).
    if fingerprint is None:
        from .signing import public_key_to_pem
        public_pem = public_key_to_pem(private_key.public_key())
        fingerprint = public_key_fingerprint(public_pem)

    # Compute chain hash over canonical form excluding seal.
    chash = chain_hash(attestation_dict)

    # Sign chain_hash bytes (R7).
    sig_b64 = signing.sign(private_key, chash)

    seal = Seal(
        chain_hash=chash,
        canonicalization="rfc8785",
        signature_algorithm="ed25519",
        signature=sig_b64,
        public_key_fingerprint=fingerprint,
        public_key_url=public_key_url,
    )

    sealed = dict(attestation_dict)
    sealed["seal"] = seal.model_dump()

    # Final structural validation including seal.
    Attestation.model_validate(sealed)
    # Roundtrip check: the chain_hash we just computed should match what the
    # canonical-form bytes hash to right now.
    expected = chain_hash(sealed)
    assert expected == chash, f"chain_hash drift: expected {chash}, got {expected}"

    return sealed


def emit_dsse(
    attestation_dict: dict[str, Any],
    *,
    custodian: str,
    public_key_url: str,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    """Emit a DSSE-wrapped Canon Attestation.

    Returns a DSSEEnvelope-shaped dict. The inner Attestation is embedded as
    base64(canonical_bytes) in the `payload` field. The signature is over
    PAE(payloadType, payload_bytes) per the DSSE spec (v0.2.0).
    """
    import base64 as _base64
    import hashlib as _hashlib

    from .schema import DSSEEnvelope

    # Set header fields for v0.2.0
    attestation_dict.setdefault("canon_version", "0.2.0")
    attestation_dict.setdefault("issued_at", _now_rfc3339())
    if "attestation_id" not in attestation_dict:
        try:
            import ulid
            attestation_dict["attestation_id"] = str(ulid.new()).upper()
        except ImportError:
            attestation_dict["attestation_id"] = uuid4().hex.upper()

    # Validate structure (without seal)
    Attestation.model_validate({**attestation_dict, "seal": None})

    private_key = keys.load_private(custodian)

    if fingerprint is None:
        from .signing import public_key_to_pem
        public_pem = public_key_to_pem(private_key.public_key())
        fingerprint = public_key_fingerprint(public_pem)

    # Canonical bytes (seal excluded)
    canonical_b = canonicalize_for_seal(attestation_dict)
    chash = "sha256:" + _hashlib.sha256(canonical_b).hexdigest()

    # DSSE signature over PAE(payloadType, canonical_bytes)
    dsse_sig = signing.sign_dsse(private_key, canonical_b)
    payload_b64 = _base64.b64encode(canonical_b).decode("ascii")

    envelope = {
        "payload_type": signing.CANON_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [{"keyid": fingerprint, "sig": dsse_sig, "public_key_url": public_key_url}],
        "chain_hash": chash,
    }
    # Structural check
    DSSEEnvelope.model_validate(envelope)
    return envelope


def canonical_bytes(sealed_attestation: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes (excluding seal) of a sealed Attestation.

    Useful for re-verifying a stored Attestation matches its declared chain_hash.
    """
    return canonicalize_for_seal(sealed_attestation)
