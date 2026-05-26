"""Ed25519 sign / verify per RFC 8032.

Spec reference: paper §8.1, R7. The signature is computed over the UTF-8
bytes of the chain_hash string (inclusive of the 'sha256:' prefix), using
the issuer's Ed25519 private key.

PEM encoding follows RFC 8410 (paper §8.1, R8).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# --- DSSE payload type ----------------------------------------------------

CANON_PAYLOAD_TYPE = "application/vnd.nora.canon.attestation+json; version=0.2.0"


# --- Key generation -------------------------------------------------------


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


# --- PEM encode / decode --------------------------------------------------


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialize public key to RFC 8410 PEM (PKIX SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    """Parse PEM-encoded Ed25519 public key."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519PublicKey, got {type(key).__name__}")
    return key


def private_key_to_pem(private_key: Ed25519PrivateKey, password: bytes | None = None) -> bytes:
    """Serialize private key to PEM. If password is provided, encrypt at-rest."""
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def private_key_from_pem(pem_bytes: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    """Parse PEM-encoded Ed25519 private key."""
    key = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Expected Ed25519PrivateKey, got {type(key).__name__}")
    return key


# --- Sign / verify --------------------------------------------------------


def sign(private_key: Ed25519PrivateKey, chain_hash: str) -> str:
    """Sign the chain_hash string and return base64-encoded signature.

    Per R7, signature is over the UTF-8 bytes of chain_hash inclusive of
    the 'sha256:' prefix.
    """
    if not chain_hash.startswith("sha256:"):
        raise ValueError("chain_hash must include the 'sha256:' prefix")
    signature_bytes = private_key.sign(chain_hash.encode("utf-8"))
    return base64.b64encode(signature_bytes).decode("ascii")


def verify(public_key: Ed25519PublicKey, chain_hash: str, signature_b64: str) -> bool:
    """Verify a base64-encoded signature against the chain_hash."""
    if not chain_hash.startswith("sha256:"):
        return False
    try:
        signature_bytes = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception:
        return False
    try:
        public_key.verify(signature_bytes, chain_hash.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


# --- DSSE sign / verify ---------------------------------------------------


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding.

    PAE = "DSSEv1\n" + enc(payloadType) + "\n" + enc(payload)
    where enc(b) = uint64_le(len(b)) + b
    """
    def enc(b: bytes) -> bytes:
        return len(b).to_bytes(8, "little") + b

    return b"DSSEv1\n" + enc(payload_type.encode("utf-8")) + b"\n" + enc(payload)


def sign_dsse(
    private_key: Ed25519PrivateKey,
    payload: bytes,
    payload_type: str = CANON_PAYLOAD_TYPE,
) -> str:
    """Sign PAE(payloadType, payload); return base64url-encoded signature (no padding)."""
    sig_bytes = private_key.sign(_pae(payload_type, payload))
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")


def verify_dsse(
    public_key: Ed25519PublicKey,
    payload: bytes,
    sig_b64url: str,
    payload_type: str = CANON_PAYLOAD_TYPE,
) -> bool:
    """Verify a DSSE signature (base64url, no padding required)."""
    try:
        # Restore padding if needed
        pad = (4 - len(sig_b64url) % 4) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_b64url + "=" * pad)
        public_key.verify(sig_bytes, _pae(payload_type, payload))
        return True
    except Exception:
        return False
