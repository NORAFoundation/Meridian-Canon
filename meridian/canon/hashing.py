"""SHA-256 chain hash and content hash helpers.

Spec reference: paper §8.1 (FIPS 180-4 SHA-256), R2 (content integrity),
R7 (canonical sealing).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonicalize import canonicalize_for_seal


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex digest of data (no prefix)."""
    return hashlib.sha256(data).hexdigest()


def content_hash(data: bytes) -> str:
    """Compute the canonical content hash for a Witness entry (R2).

    Returns 'sha256:<64-hex>' as required by the WitnessEntry schema.
    """
    return f"sha256:{sha256_hex(data)}"


def chain_hash(attestation: dict[str, Any]) -> str:
    """Compute the chain_hash for the Seal block (R7).

    Defined as SHA-256 of the RFC 8785 canonical serialization of the
    Attestation with the seal field excluded.
    """
    canonical = canonicalize_for_seal(attestation)
    return f"sha256:{sha256_hex(canonical)}"


def public_key_fingerprint(public_key_pem: bytes) -> str:
    """Compute the fingerprint of a PEM-encoded Ed25519 public key.

    Returns 'sha256:<64-hex>' suitable for the seal.public_key_fingerprint field (R8).
    """
    return f"sha256:{sha256_hex(public_key_pem)}"
