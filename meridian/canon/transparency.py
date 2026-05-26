"""Optional Rekor transparency log integration for Canon Attestations.

After sealing, publish the attestation to Rekor (self-hosted or public).
This provides an external witness: a third party saw this attestation at
this timestamp with this hash — and their log is independently verifiable.

WARNING: Public Rekor (rekor.sigstore.dev) makes attestation IDs and
chain hashes publicly visible. Use self-hosted Rekor for privileged matters.

Self-hosted Rekor:
    docker run -p 3000:3000 gcr.io/projectsigstore/rekor-server:latest

Feature flag: MERIDIAN_REKOR_URL env var (default: self-hosted at localhost:3000)
              Set MERIDIAN_REKOR_URL=https://rekor.sigstore.dev for public log.
              Set MERIDIAN_REKOR_ENABLED=0 to disable entirely.

Install for Sigstore signing path: pip install sigstore>=3.0
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

try:
    import sigstore as _sigstore
    _SIGSTORE_AVAILABLE = True
except ImportError:
    _SIGSTORE_AVAILABLE = False


DEFAULT_REKOR_URL = os.environ.get("MERIDIAN_REKOR_URL", "http://localhost:3000")


@dataclass
class RekorEntry:
    """Metadata for a Rekor transparency log entry."""
    log_index: int
    log_id: str
    entry_uuid: str
    integrated_time: int    # Unix timestamp
    verification_url: str
    rekor_url: str


@dataclass
class RekorPublishResult:
    """Result of publishing to Rekor. is_published=False on failure or when disabled."""
    is_published: bool
    entry: Optional[RekorEntry] = None
    error: Optional[str] = None


def publish_attestation(
    sealed_attestation: dict,
    *,
    public_key_pem: bytes,
    rekor_url: Optional[str] = None,
) -> RekorPublishResult:
    """Submit a sealed Canon Attestation to a Rekor transparency log.

    Args:
        sealed_attestation: Fully sealed Canon Attestation dict (with seal block)
        public_key_pem: PEM-encoded Ed25519 public key of the issuer
        rekor_url: Rekor server URL. Defaults to MERIDIAN_REKOR_URL env var or localhost:3000.

    Returns:
        RekorPublishResult. On success, entry contains log metadata to store
        in the rekor_entries table.
    """
    enabled = os.environ.get("MERIDIAN_REKOR_ENABLED", "1").strip()
    if enabled == "0":
        return RekorPublishResult(is_published=False, error="Rekor disabled via MERIDIAN_REKOR_ENABLED=0")

    url = rekor_url or DEFAULT_REKOR_URL

    # Serialize attestation to bytes for Rekor payload
    payload_bytes = json.dumps(sealed_attestation, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    # Signature from the seal block
    sig_b64 = sealed_attestation.get("seal", {}).get("signature", "")
    pub_key_b64 = base64.b64encode(public_key_pem).decode("ascii")

    # Rekor rekord v0.0.1 format
    rekor_body = {
        "kind": "rekord",
        "apiVersion": "0.0.1",
        "spec": {
            "signature": {
                "format": "x509",
                "content": sig_b64,
                "publicKey": {"content": pub_key_b64},
            },
            "data": {"content": payload_b64},
        },
    }

    body_bytes = json.dumps(rekor_body).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/api/v1/log/entries",
        data=body_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
    except urllib.error.URLError as e:
        return RekorPublishResult(
            is_published=False,
            error=f"Rekor server unreachable at {url}: {e}",
        )
    except Exception as e:
        return RekorPublishResult(is_published=False, error=str(e))

    try:
        uuid = next(iter(result))
        entry_data = result[uuid]
        entry = RekorEntry(
            log_index=entry_data["logIndex"],
            log_id=entry_data["logID"],
            entry_uuid=uuid,
            integrated_time=entry_data["integratedTime"],
            verification_url=f"{url}/api/v1/log/entries/{uuid}",
            rekor_url=url,
        )
        return RekorPublishResult(is_published=True, entry=entry)
    except (KeyError, StopIteration) as e:
        return RekorPublishResult(is_published=False, error=f"Unexpected Rekor response format: {e}")


def verify_log_entry(
    entry_uuid: str,
    *,
    rekor_url: Optional[str] = None,
) -> dict:
    """Fetch and return a Rekor log entry by UUID for independent verification."""
    url = rekor_url or DEFAULT_REKOR_URL
    req = urllib.request.Request(f"{url}/api/v1/log/entries/{entry_uuid}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Could not fetch Rekor entry {entry_uuid}: {e}") from e
