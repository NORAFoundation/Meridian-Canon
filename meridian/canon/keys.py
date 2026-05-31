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

import json
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


def load_trust_store(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load an out-of-band trust store mapping issuer -> pinned key fingerprint.

    AUDIT-FIX (K2#1): the trust store is the verifier's OUT-OF-BAND anchor.
    It is obtained through a channel independent of any attestation's
    `public_key_url` (a checked-in allowlist, a distributed config, an
    operator-curated file) and is what `walk(..., trust_anchor=...)` compares
    the fetched key's fingerprint against. Without it, walk() proves integrity
    but NOT authenticity (the URL-substitution forgery is undefeated).

    File format: a flat JSON object mapping each issuer identifier (an issuer
    id string and/or its `public_key_url`) to the expected key fingerprint:

        {
          "acme-corp-2026": "sha256:<64-hex>",
          "https://acme.example/keys/2026.pem": "sha256:<64-hex>"
        }

    Returns the parsed mapping. Raises ValueError with a clear, actionable
    message on any malformed input (missing file, non-JSON, non-object root,
    non-string keys/values, or fingerprints not in `sha256:<hex>` form).
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise ValueError(f"trust store not found: {p}") from e
    except OSError as e:
        raise ValueError(f"cannot read trust store {p}: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"trust store {p} is not valid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"trust store {p} must be a JSON object mapping issuer -> fingerprint, "
            f"got {type(data).__name__}"
        )

    store: dict[str, str] = {}
    for issuer, fp in data.items():
        if not isinstance(issuer, str) or not issuer:
            raise ValueError(
                f"trust store {p} has a non-string or empty issuer key: {issuer!r}"
            )
        if not isinstance(fp, str):
            raise ValueError(
                f"trust store {p} fingerprint for issuer {issuer!r} must be a string, "
                f"got {type(fp).__name__}"
            )
        if not fp.startswith("sha256:") or len(fp) != len("sha256:") + 64:
            raise ValueError(
                f"trust store {p} fingerprint for issuer {issuer!r} is not a valid "
                f"'sha256:<64-hex>' value: {fp!r}"
            )
        store[issuer] = fp
    return store


def revoke(custodian: str) -> None:
    """Remove the private key from Keychain. Public PEM remains for verifying
    pre-revocation Attestations (paper §8.2 'Revocation')."""
    try:
        keyring.delete_password(KEYRING_SERVICE, custodian)
    except keyring.errors.PasswordDeleteError:
        pass
