"""Key generation, storage, and publication.

Spec reference: paper §8.2 (key lifecycle), R8 (key discoverability).

Private keys are stored in the OS credential store via the keyring library:
  - macOS:   Keychain
  - Windows: Windows Credential Manager
  - Linux:   SecretService (GNOME Keyring / KWallet) or file-based fallback

For CI / headless environments, set the env var:
  PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring
and install: pip install keyrings.alt

Public keys are exported to PEM (RFC 8410) and must be hosted at a stable
URL declared in every Seal's public_key_url field.

Usage:
    private, public, fingerprint = keygen("acme-corp-2026")
    # Public PEM is written to ~/.meridian/keys/<fingerprint>.pem
    # Private key lives in the OS credential store under service 'meridian-canon',
    # account = custodian name.
"""

from __future__ import annotations

import os
from pathlib import Path

import keyring
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import signing
from .hashing import public_key_fingerprint


KEYRING_SERVICE = "meridian-canon"
DEFAULT_KEY_DIR = Path(os.environ.get("MERIDIAN_KEY_DIR", str(Path.home() / ".meridian" / "keys")))


def _ensure_dir() -> Path:
    DEFAULT_KEY_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_KEY_DIR


def keygen(custodian: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Generate a fresh Ed25519 keypair for the given custodian.

    Stores the private key in Keychain (account = custodian).
    Writes the public PEM to <DEFAULT_KEY_DIR>/<fingerprint>.pem.
    Returns (private_key, public_key, fingerprint).
    """
    private_key, public_key = signing.generate_keypair()
    pem_private = signing.private_key_to_pem(private_key)
    pem_public = signing.public_key_to_pem(public_key)
    fingerprint = public_key_fingerprint(pem_public)

    # Store private key in Keychain. The Keychain entry's "password" is
    # the PEM bytes themselves; access is controlled by the OS.
    keyring.set_password(KEYRING_SERVICE, custodian, pem_private.decode("ascii"))

    # Write public PEM to disk for publication.
    pem_dir = _ensure_dir()
    pem_path = pem_dir / f"{fingerprint.replace(':', '_')}.pem"
    pem_path.write_bytes(pem_public)

    return private_key, public_key, fingerprint


def load_private(custodian: str) -> Ed25519PrivateKey:
    """Load the private key for the given custodian from Keychain."""
    pem = keyring.get_password(KEYRING_SERVICE, custodian)
    if pem is None:
        raise KeyError(f"No Keychain entry for custodian {custodian!r}")
    return signing.private_key_from_pem(pem.encode("ascii"))


def load_public_pem(fingerprint: str) -> bytes:
    """Load a published public key by fingerprint from the local PEM cache."""
    pem_path = DEFAULT_KEY_DIR / f"{fingerprint.replace(':', '_')}.pem"
    if not pem_path.exists():
        raise FileNotFoundError(f"No PEM for fingerprint {fingerprint} at {pem_path}")
    return pem_path.read_bytes()


def revoke(custodian: str) -> None:
    """Remove the private key from Keychain. Public PEM remains for verifying
    pre-revocation Attestations (paper §8.2 'Revocation')."""
    try:
        keyring.delete_password(KEYRING_SERVICE, custodian)
    except keyring.errors.PasswordDeleteError:
        pass
