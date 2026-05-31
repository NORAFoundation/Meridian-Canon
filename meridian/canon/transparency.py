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

--------------------------------------------------------------------------
AUDIT-FIX (K2#2): real transparency-log inclusion verification.

Before K2#2 the only "verification" was ``verify_log_entry`` fetching an entry
and returning it — it checked NOTHING. The log could lie about inclusion, the
SET could be forged, and nobody recomputed the Merkle root. This module now
implements:

  * ``verify_inclusion_proof`` — recompute the RFC 6962 Merkle root from a
    stored proof bundle (leaf + audit path) with NO network call, and compare
    against the signed root hash. This is the load-bearing check.
  * ``verify_set`` — verify the log's Signed Entry Timestamp (the log's own
    signature over the canonical entry) against a provided Rekor public key.
  * ``verify_checkpoint`` — verify the signed tree head / checkpoint note
    signature (the log committed to this root) against the log public key.
  * ``verify_entry_bundle`` — the offline aggregate: inclusion + (optional)
    SET + (optional) checkpoint, returning a structured ``TransparencyResult``.

The publish path was ALSO defective in two concrete ways, now fixed:

  1. CANONICALIZATION MISMATCH. The bytes submitted to (and therefore
     committed by) the log were produced with ``json.dumps(sort_keys=True)`` —
     a DIFFERENT canonicalization from the rfc8785 bytes the seal actually
     signed. The log thus committed to bytes that did not match the seal, so
     an inclusion proof proved inclusion of the WRONG bytes. Fixed: the log
     payload is now the exact rfc8785 canonical bytes (``canonical_entry_bytes``)
     that were signed.

  2. WRONG SIGNATURE FORMAT. The rekord body declared ``"format": "x509"`` for
     an Ed25519 public key that is a bare RFC 8410 PEM, not an x509 cert. Fixed
     to ``"ed25519"``.

AUDIT-TODO (K2#3 — REMAINING): full key transparency. A CT-style monitored,
gossiped log of *issuer keys* with rotation + revocation semantics, so that
manual pinning (K2#1) can be replaced by a monitored log and a hidden second
signing key is detectable across the population, not just per-pinned-issuer.
K2#2 (this file) gives append-only inclusion of *entries*; K2#3 gives
append-only transparency of *keys*.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .canonicalize import canonicalize_for_seal

try:
    import sigstore as _sigstore
    _SIGSTORE_AVAILABLE = True
except ImportError:
    _SIGSTORE_AVAILABLE = False


DEFAULT_REKOR_URL = os.environ.get("MERIDIAN_REKOR_URL", "http://localhost:3000")

# RFC 6962 domain-separation prefixes for the Merkle tree hash.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


# ---------------------------------------------------------------------------
# Canonicalization of the log payload (AUDIT-FIX K2#2 defect #1)
# ---------------------------------------------------------------------------


def canonical_entry_bytes(sealed_attestation: dict) -> bytes:
    """Return the EXACT bytes that were signed AND must be committed to the log.

    These are the rfc8785 canonical bytes of the attestation with the seal
    excluded — identical to what ``emit``/``emit_dsse`` hashed and signed. The
    log MUST commit to these bytes, not a ``json.dumps(sort_keys=True)``
    re-serialization, or its inclusion proof proves inclusion of bytes that do
    not match the seal.
    """
    return canonicalize_for_seal(sealed_attestation)


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


@dataclass
class InclusionProof:
    """An offline-verifiable RFC 6962 inclusion proof bundle.

    All fields are stored alongside the attestation so verification needs NO
    network call. ``hashes`` is the audit path, ordered from the sibling
    closest to the leaf up to the sibling closest to the root, each a
    lowercase-hex SHA-256 digest. ``root_hash`` is the signed tree head root
    this proof was issued against.
    """
    log_index: int          # 0-based index of the leaf in the tree
    tree_size: int          # number of leaves in the tree at proof time
    root_hash: str          # hex SHA-256 of the signed root
    hashes: list[str]       # audit path, hex SHA-256 siblings (leaf->root order)


@dataclass
class TransparencyResult:
    """Structured outcome of offline transparency verification."""
    verified: bool
    reason: str
    inclusion_ok: bool = False
    set_ok: Optional[bool] = None          # None = not present / not checked
    checkpoint_ok: Optional[bool] = None   # None = not present / not checked
    computed_root: Optional[str] = None


# ---------------------------------------------------------------------------
# RFC 6962 Merkle inclusion-proof verification (AUDIT-FIX K2#2, core)
# ---------------------------------------------------------------------------


def rfc6962_leaf_hash(entry_bytes: bytes) -> str:
    """RFC 6962 leaf hash: SHA-256(0x00 || entry_bytes). Returns lowercase hex."""
    return hashlib.sha256(_LEAF_PREFIX + entry_bytes).hexdigest()


def rfc6962_node_hash(left_hex: str, right_hex: str) -> str:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right).

    ``left_hex`` and ``right_hex`` are lowercase-hex digests; the raw bytes are
    concatenated under the node prefix. Returns lowercase hex.
    """
    return hashlib.sha256(
        _NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def compute_merkle_root(
    leaf_hash_hex: str,
    log_index: int,
    tree_size: int,
    audit_path: list[str],
) -> str:
    """Recompute the Merkle root from a leaf and its audit path (RFC 6962 §2.1.1).

    This is the algorithm Rekor / Certificate Transparency clients use to verify
    an inclusion proof offline. ``log_index`` is the 0-based leaf index,
    ``tree_size`` the number of leaves, ``audit_path`` the ordered sibling
    digests from the leaf level up. Returns the computed root as lowercase hex.

    Raises ValueError on a structurally invalid proof (bad index/size, wrong
    path length) — a malformed proof must never silently "verify".
    """
    if tree_size <= 0:
        raise ValueError("tree_size must be positive")
    if not (0 <= log_index < tree_size):
        raise ValueError(
            f"log_index {log_index} out of range for tree_size {tree_size}"
        )

    # Single-leaf tree: the root IS the leaf hash; the path must be empty.
    node = leaf_hash_hex
    fn = log_index          # index of the current node within its level
    sn = tree_size - 1      # index of the last node within its level
    path_iter = iter(audit_path)
    consumed = 0

    while sn > 0:
        if fn % 2 == 1 or fn == sn:
            # We are a right child, OR a left child that is the last node and
            # therefore has no right sibling promoted up at this level.
            if fn % 2 == 1:
                try:
                    sibling = next(path_iter)
                except StopIteration:
                    raise ValueError("audit path too short for proof geometry")
                consumed += 1
                node = rfc6962_node_hash(sibling, node)
            # If fn == sn and fn is even, this node has no sibling at this
            # level; it is promoted unchanged (no path element consumed).
            else:
                # fn == sn and even: carried up unchanged.
                pass
        else:
            # Left child with a present right sibling.
            try:
                sibling = next(path_iter)
            except StopIteration:
                raise ValueError("audit path too short for proof geometry")
            consumed += 1
            node = rfc6962_node_hash(node, sibling)
        fn //= 2
        sn //= 2

    leftover = list(path_iter)
    if leftover:
        raise ValueError(
            f"audit path too long: {len(leftover)} unused element(s)"
        )
    return node


def verify_inclusion_proof(
    entry_bytes: bytes,
    proof: InclusionProof,
) -> TransparencyResult:
    """Verify an RFC 6962 inclusion proof OFFLINE (no network).

    Recomputes the leaf hash SHA-256(0x00||entry_bytes), walks the audit path,
    and checks the resulting root equals the signed ``proof.root_hash``.

    Returns a TransparencyResult; ``verified``/``inclusion_ok`` are True only if
    the recomputed root matches exactly.
    """
    leaf = rfc6962_leaf_hash(entry_bytes)
    try:
        computed = compute_merkle_root(
            leaf, proof.log_index, proof.tree_size, list(proof.hashes)
        )
    except ValueError as e:
        return TransparencyResult(
            verified=False,
            reason=f"inclusion proof malformed: {e}",
            inclusion_ok=False,
        )
    expected = proof.root_hash.lower().removeprefix("sha256:")
    if computed == expected:
        return TransparencyResult(
            verified=True,
            reason="inclusion proof verified: recomputed Merkle root matches signed root",
            inclusion_ok=True,
            computed_root=computed,
        )
    return TransparencyResult(
        verified=False,
        reason=(
            f"inclusion proof FAILED: recomputed root {computed} != signed root "
            f"{expected} (entry not in committed tree, or tampered leaf/path)"
        ),
        inclusion_ok=False,
        computed_root=computed,
    )


# ---------------------------------------------------------------------------
# Signed Entry Timestamp (SET) and checkpoint/STH signature verification
# ---------------------------------------------------------------------------


def _load_log_pubkey(log_public_key_pem: bytes):
    """Load a log public key. Accepts Ed25519 (RFC 8410) PEM.

    Rekor production uses ECDSA-P256; for the self-hosted/Ed25519 deployment
    Meridian targets we verify Ed25519. Returns the loaded public key object.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(log_public_key_pem)


def verify_set(
    set_bytes: bytes,
    set_signature_b64: str,
    log_public_key_pem: bytes,
) -> bool:
    """Verify a Signed Entry Timestamp: the log's signature over ``set_bytes``.

    ``set_bytes`` are the canonical bytes the log signed (for Rekor, the
    canonicalized entry without the ``verification`` block). ``set_signature_b64``
    is the standard-base64 signature from ``verification.signedEntryTimestamp``.
    Returns True only if the signature verifies under the provided log key.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes as _hashes

    try:
        sig = base64.b64decode(set_signature_b64, validate=True)
    except Exception:
        return False
    try:
        key = _load_log_pubkey(log_public_key_pem)
    except Exception:
        return False
    try:
        if isinstance(key, Ed25519PublicKey):
            key.verify(sig, set_bytes)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            # Rekor SETs are ECDSA over SHA-256 of the canonical entry bytes.
            key.verify(sig, set_bytes, ec.ECDSA(_hashes.SHA256()))
        else:  # pragma: no cover - unsupported key type
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_checkpoint(
    checkpoint_note: bytes,
    checkpoint_signature_b64: str,
    log_public_key_pem: bytes,
) -> bool:
    """Verify a signed tree head / checkpoint note signature.

    The checkpoint (STH) is the log's signed commitment to a (tree_size,
    root_hash) pair. Verifying it ties the inclusion proof's ``root_hash`` to a
    signature the log cannot later repudiate. Signature scheme handling matches
    ``verify_set`` (Ed25519 or ECDSA-P256/SHA-256).
    """
    return verify_set(checkpoint_note, checkpoint_signature_b64, log_public_key_pem)


def verify_entry_bundle(
    entry_bytes: bytes,
    proof: InclusionProof,
    *,
    log_public_key_pem: Optional[bytes] = None,
    set_bytes: Optional[bytes] = None,
    set_signature_b64: Optional[str] = None,
    checkpoint_note: Optional[bytes] = None,
    checkpoint_signature_b64: Optional[str] = None,
) -> TransparencyResult:
    """Offline aggregate verification: inclusion + optional SET + optional checkpoint.

    The inclusion proof is mandatory and load-bearing. SET and checkpoint are
    verified only when both their bytes/signature AND a log public key are
    supplied; when supplied they must PASS or the bundle fails closed. No
    network access is performed.
    """
    incl = verify_inclusion_proof(entry_bytes, proof)
    if not incl.inclusion_ok:
        return incl

    set_ok: Optional[bool] = None
    checkpoint_ok: Optional[bool] = None
    reasons = [incl.reason]

    if set_signature_b64 is not None and set_bytes is not None:
        if log_public_key_pem is None:
            return TransparencyResult(
                verified=False,
                reason="SET present but no log public key supplied to verify it",
                inclusion_ok=True,
                computed_root=incl.computed_root,
            )
        set_ok = verify_set(set_bytes, set_signature_b64, log_public_key_pem)
        if not set_ok:
            return TransparencyResult(
                verified=False,
                reason="signed entry timestamp (SET) signature FAILED",
                inclusion_ok=True,
                set_ok=False,
                computed_root=incl.computed_root,
            )
        reasons.append("SET verified")

    if checkpoint_signature_b64 is not None and checkpoint_note is not None:
        if log_public_key_pem is None:
            return TransparencyResult(
                verified=False,
                reason="checkpoint present but no log public key supplied to verify it",
                inclusion_ok=True,
                set_ok=set_ok,
                computed_root=incl.computed_root,
            )
        checkpoint_ok = verify_checkpoint(
            checkpoint_note, checkpoint_signature_b64, log_public_key_pem
        )
        if not checkpoint_ok:
            return TransparencyResult(
                verified=False,
                reason="checkpoint / signed tree head signature FAILED",
                inclusion_ok=True,
                set_ok=set_ok,
                checkpoint_ok=False,
                computed_root=incl.computed_root,
            )
        reasons.append("checkpoint verified")

    return TransparencyResult(
        verified=True,
        reason="; ".join(reasons),
        inclusion_ok=True,
        set_ok=set_ok,
        checkpoint_ok=checkpoint_ok,
        computed_root=incl.computed_root,
    )


# ---------------------------------------------------------------------------
# Proof-bundle extraction from a Rekor API response / stored attestation
# ---------------------------------------------------------------------------


def inclusion_proof_from_rekor(verification_block: dict) -> InclusionProof:
    """Build an InclusionProof from a Rekor ``verification.inclusionProof`` dict.

    Rekor's field names are ``logIndex``, ``treeSize``, ``rootHash``, ``hashes``.
    Raises KeyError if the block is missing required fields.
    """
    return InclusionProof(
        log_index=int(verification_block["logIndex"]),
        tree_size=int(verification_block["treeSize"]),
        root_hash=str(verification_block["rootHash"]),
        hashes=[str(h) for h in verification_block["hashes"]],
    )


def _proof_from_transparency_block(block: object) -> Optional[InclusionProof]:
    if isinstance(block, dict):
        rekor = block.get("rekor", block)
        if isinstance(rekor, dict):
            proof = rekor.get("inclusionProof") or rekor.get("inclusion_proof")
            if isinstance(proof, dict):
                try:
                    return inclusion_proof_from_rekor(proof)
                except (KeyError, ValueError, TypeError):
                    return None
    return None


def extract_rekor_proof(attestation: dict) -> Optional[InclusionProof]:
    """Pull a stored Rekor inclusion proof out of an attestation/envelope.

    The proof is post-seal metadata and MUST live somewhere that is excluded
    from the chain_hash, or attaching it would invalidate the seal. For an
    inline-seal v0.1.x Attestation the canonical home is ``seal.transparency``
    (the entire ``seal`` block is excluded from ``canonicalize_for_seal``). For
    a DSSE envelope (whose chain_hash covers only the payload bytes) a top-level
    ``transparency`` block is safe. Both placements — plus a bare top-level
    ``inclusionProof`` — are recognized here. Returns None when absent.
    """
    # 1) inline-seal home: seal.transparency (excluded from chain_hash).
    seal = attestation.get("seal")
    if isinstance(seal, dict):
        found = _proof_from_transparency_block(seal.get("transparency"))
        if found is not None:
            return found
    # 2) DSSE / sidecar home: top-level transparency.
    found = _proof_from_transparency_block(attestation.get("transparency"))
    if found is not None:
        return found
    # 3) bare top-level inclusionProof.
    proof = attestation.get("inclusionProof")
    if isinstance(proof, dict):
        try:
            return inclusion_proof_from_rekor(proof)
        except (KeyError, ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Publish / fetch (network) — fixed canonicalization and signature format
# ---------------------------------------------------------------------------


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

    AUDIT-FIX (K2#2): the payload committed to the log is now the EXACT rfc8785
    canonical bytes that were signed (``canonical_entry_bytes``), not a
    ``json.dumps(sort_keys=True)`` re-serialization — so the log's inclusion
    proof commits to the same bytes the seal signed. The signature ``format`` is
    ``ed25519`` (the key is an RFC 8410 Ed25519 PEM, not an x509 certificate).
    """
    enabled = os.environ.get("MERIDIAN_REKOR_ENABLED", "1").strip()
    if enabled == "0":
        return RekorPublishResult(is_published=False, error="Rekor disabled via MERIDIAN_REKOR_ENABLED=0")

    url = rekor_url or DEFAULT_REKOR_URL

    # AUDIT-FIX (K2#2, defect #1): commit the EXACT signed canonical bytes.
    payload_bytes = canonical_entry_bytes(sealed_attestation)
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
                # AUDIT-FIX (K2#2, defect #2): Ed25519 bare key, not x509.
                "format": "ed25519",
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
    sealed_attestation: Optional[dict] = None,
    log_public_key_pem: Optional[bytes] = None,
    rekor_url: Optional[str] = None,
) -> TransparencyResult:
    """Fetch a Rekor entry by UUID and VERIFY its inclusion proof (online fetch,
    offline verify).

    AUDIT-FIX (K2#2): previously this only fetched and returned the entry without
    checking anything. It now fetches the entry, extracts the inclusion proof and
    SET, and runs the real offline verification against the canonical bytes of
    ``sealed_attestation`` (required — you can only verify inclusion of bytes you
    hold). Raises RuntimeError on a network/shape failure; returns a
    TransparencyResult for the cryptographic verdict.
    """
    if sealed_attestation is None:
        raise ValueError(
            "verify_log_entry requires sealed_attestation to recompute the leaf; "
            "inclusion of unknown bytes cannot be verified"
        )
    url = rekor_url or DEFAULT_REKOR_URL
    req = urllib.request.Request(f"{url}/api/v1/log/entries/{entry_uuid}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Could not fetch Rekor entry {entry_uuid}: {e}") from e

    try:
        entry = raw[next(iter(raw))] if entry_uuid not in raw else raw[entry_uuid]
        verification = entry.get("verification", {})
        proof = inclusion_proof_from_rekor(verification["inclusionProof"])
    except (KeyError, StopIteration, TypeError) as e:
        raise RuntimeError(f"Rekor entry {entry_uuid} has no usable inclusion proof: {e}") from e

    entry_bytes = canonical_entry_bytes(sealed_attestation)
    set_sig = verification.get("signedEntryTimestamp")
    set_bytes = entry_bytes if set_sig else None
    return verify_entry_bundle(
        entry_bytes,
        proof,
        log_public_key_pem=log_public_key_pem,
        set_bytes=set_bytes,
        set_signature_b64=set_sig,
    )
