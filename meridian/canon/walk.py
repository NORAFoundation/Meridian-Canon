"""Reference verifier: seven-step falsification protocol.

Spec reference: paper §8.3 + CANON.md §14.

A recipient possessing an Attestation and ordinary network access can walk
this verifier without any cooperation from the issuer. Steps 1-6 yield a
deterministic pass/fail; step 7 surfaces the declined-challenges inventory
for the recipient's substantive review and is explicitly informational.

CLI:
    python -m meridian.canon.walk path/to/attestation.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from . import signing
from .canonicalize import canonicalize_for_seal
from .hashing import sha256_hex


CANON_VERSION_SUPPORTED = {"0.1.0", "0.1.1", "0.2.0"}


def _step1_public_key_fetch(seal: dict[str, Any]) -> tuple[str, bytes | None]:
    """Fetch PEM from public_key_url and verify SHA-256 fingerprint matches public_key_fingerprint."""
    url = seal["public_key_url"]
    declared = seal["public_key_fingerprint"]
    try:
        if url.startswith("file://"):
            pem = Path(url.removeprefix("file://")).read_bytes()
        else:
            with urlopen(url, timeout=10) as resp:
                pem = resp.read()
    except Exception as e:
        return f"fail: cannot fetch {url}: {e}", None
    actual = f"sha256:{sha256_hex(pem)}"
    if actual != declared:
        return f"fail: fingerprint mismatch (got {actual}, expected {declared})", None
    return "pass", pem


def _step2_signature_verify(pem: bytes, seal: dict[str, Any]) -> str:
    public_key = signing.public_key_from_pem(pem)
    if signing.verify(public_key, seal["chain_hash"], seal["signature"]):
        return "pass"
    return "fail: Ed25519 signature does not verify"


def _step3_chain_hash_recompute(attestation: dict[str, Any]) -> str:
    canonical = canonicalize_for_seal(attestation)
    expected = f"sha256:{sha256_hex(canonical)}"
    declared = attestation["seal"]["chain_hash"]
    if expected == declared:
        return "pass"
    return f"fail: chain_hash mismatch (computed {expected}, declared {declared})"


def _step4_witness_content_hashes(attestation: dict[str, Any]) -> dict[str, int]:
    """For each WitnessEntry with a content_ref, fetch and re-hash."""
    verified, failed = 0, 0
    for entry in attestation.get("witness", []):
        ref = entry.get("content_ref")
        declared = entry.get("content_hash", "")
        if not declared.startswith("sha256:"):
            failed += 1
            continue
        if ref is None:
            inline = entry.get("content_inline")
            if inline is None:
                failed += 1
                continue
            import base64
            try:
                raw = base64.b64decode(inline)
            except Exception:
                failed += 1
                continue
        else:
            try:
                if ref.startswith("file://"):
                    raw = Path(ref.removeprefix("file://")).read_bytes()
                else:
                    with urlopen(ref, timeout=10) as resp:
                        raw = resp.read()
            except Exception:
                failed += 1
                continue
        if f"sha256:{sha256_hex(raw)}" == declared:
            verified += 1
        else:
            failed += 1
    return {"verified": verified, "failed": failed}


def _step5_supports_resolution(attestation: dict[str, Any]) -> str:
    """R3: every claim's supports must resolve to a witness observation_id
    or to an earlier claim_id. Forward references prohibited."""
    obs_ids = {w["observation_id"] for w in attestation.get("witness", [])}
    seen_claims: set[str] = set()
    for claim in attestation.get("findings", {}).get("claims", []):
        for support in claim.get("supports", []):
            if support not in obs_ids and support not in seen_claims:
                return f"fail: unresolved support {support} in claim {claim.get('claim_id')}"
        seen_claims.add(claim["claim_id"])
    return "pass"


def _step6_refutation_targets(attestation: dict[str, Any]) -> str:
    """Refutation challenge targets must resolve to claims in this Attestation."""
    claim_ids = {c["claim_id"] for c in attestation.get("findings", {}).get("claims", [])}
    for ch in attestation.get("refutation", {}).get("challenges", []):
        for target in ch.get("targets", []):
            if target not in claim_ids:
                return f"fail: challenge {ch.get('challenge_id')} targets unresolved {target}"
    return "pass"


def _step7_coverage_assessment(attestation: dict[str, Any]) -> str:
    """Informational only (paper §8.3): surfaces declined-challenge inventory.

    Canon requires that the inventory be present, not that the recipient
    finds the declines acceptable. Recipients must judge.
    """
    cov = attestation.get("refutation", {}).get("coverage", {})
    declined = cov.get("declined", [])
    return f"informational: {len(declined)} declined challenge type(s)"


def walk_dsse(envelope: dict[str, Any]) -> dict[str, Any]:
    """Walk a v0.2.0 DSSE envelope. Returns a verdict dict (same shape as walk())."""
    import base64 as _base64

    from . import signing as _signing

    # Step 0: basic shape check
    if "payload" not in envelope or "signatures" not in envelope:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step0_envelope_shape": "fail: missing payload or signatures"}}

    sigs = envelope.get("signatures", [])
    if not sigs:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step0_signatures": "fail: empty signatures array"}}

    sig_entry = sigs[0]
    keyid = sig_entry.get("keyid", "")
    url = sig_entry.get("public_key_url", "")

    # Step 1: public key fetch + fingerprint check
    try:
        if url.startswith("file://"):
            from pathlib import Path as _Path
            pem = _Path(url.removeprefix("file://")).read_bytes()
        else:
            from urllib.request import urlopen as _urlopen
            with _urlopen(url, timeout=10) as resp:
                pem = resp.read()
    except Exception as e:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step1_public_key_fetch": f"fail: {e}"}}

    actual_fingerprint = f"sha256:{sha256_hex(pem)}"
    if actual_fingerprint != keyid:
        s1 = f"fail: fingerprint mismatch (got {actual_fingerprint}, declared {keyid})"
    else:
        s1 = "pass"

    # Decode payload bytes
    try:
        payload_bytes = _base64.b64decode(envelope["payload"])
    except Exception as e:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step1_public_key_fetch": s1, "step2_dsse_signature": f"fail: payload decode: {e}"}}

    # Step 2: DSSE signature verify
    public_key = _signing.public_key_from_pem(pem)
    payload_type = envelope.get("payload_type", _signing.CANON_PAYLOAD_TYPE)
    sig_b64url = sig_entry.get("sig", "")
    s2 = "pass" if _signing.verify_dsse(public_key, payload_bytes, sig_b64url, payload_type) else "fail: DSSE signature does not verify"

    # Step 3: chain hash
    declared_chain = envelope.get("chain_hash", "")
    expected_chain = f"sha256:{sha256_hex(payload_bytes)}"
    s3 = "pass" if expected_chain == declared_chain else f"fail: chain_hash mismatch (computed {expected_chain}, declared {declared_chain})"

    # Decode inner attestation
    try:
        import json as _json
        inner = _json.loads(payload_bytes)
    except Exception as e:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step1_public_key_fetch": s1, "step2_dsse_signature": s2,
                          "step3_chain_hash": s3, "step4_inner_parse": f"fail: {e}"}}

    s4 = _step4_witness_content_hashes(inner)
    s5 = _step5_supports_resolution(inner)
    s6 = _step6_refutation_targets(inner)
    s7 = _step7_coverage_assessment(inner)

    binary_steps = [s1, s2, s3, s5, s6]
    valid = all(s == "pass" for s in binary_steps) and s4["failed"] == 0

    return {
        "verdict": "valid" if valid else "invalid",
        "canon_version": inner.get("canon_version", "0.2.0"),
        "attestation_id": inner.get("attestation_id"),
        "steps": {
            "step1_public_key_fetch": s1,
            "step2_dsse_signature": s2,
            "step3_chain_hash": s3,
            "step4_witness_content_hashes": s4,
            "step5_supports_resolution": s5,
            "step6_refutation_targets": s6,
            "step7_coverage_assessment": s7,
        },
    }


def walk(attestation: dict[str, Any]) -> dict[str, Any]:
    """Run the seven-step falsification protocol. Returns a verdict dict.

    Accepts both inline-seal (v0.1.x) Attestations and v0.2.0 DSSE envelopes.
    DSSE envelopes are detected by the presence of a top-level `payload` field.
    """
    # Dispatch: DSSE envelope vs inline-seal Attestation
    if "payload" in attestation and "payload_type" in attestation:
        return walk_dsse(attestation)

    if attestation.get("canon_version") not in CANON_VERSION_SUPPORTED:
        return {
            "verdict": "invalid",
            "canon_version": attestation.get("canon_version"),
            "attestation_id": attestation.get("attestation_id"),
            "steps": {"step0_canon_version": f"fail: unsupported {attestation.get('canon_version')}"},
        }
    seal = attestation.get("seal")
    if not seal:
        return {
            "verdict": "invalid",
            "canon_version": attestation.get("canon_version"),
            "attestation_id": attestation.get("attestation_id"),
            "steps": {"step0_seal_present": "fail: no seal"},
        }

    s1_msg, pem = _step1_public_key_fetch(seal)
    s2 = _step2_signature_verify(pem, seal) if pem else "fail: no public key"
    s3 = _step3_chain_hash_recompute(attestation)
    s4 = _step4_witness_content_hashes(attestation)
    s5 = _step5_supports_resolution(attestation)
    s6 = _step6_refutation_targets(attestation)
    s7 = _step7_coverage_assessment(attestation)

    binary_steps = [s1_msg, s2, s3, s5, s6]
    valid = all(s == "pass" for s in binary_steps) and s4["failed"] == 0

    return {
        "verdict": "valid" if valid else "invalid",
        "canon_version": attestation["canon_version"],
        "attestation_id": attestation["attestation_id"],
        "steps": {
            "step1_public_key_fetch": s1_msg,
            "step2_signature_verify": s2,
            "step3_chain_hash_recompute": s3,
            "step4_witness_content_hashes": s4,
            "step5_supports_resolution": s5,
            "step6_refutation_targets": s6,
            "step7_coverage_assessment": s7,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="meridian.canon.walk")
    parser.add_argument("path", type=Path, help="Path to the Attestation JSON")
    parser.add_argument("--quiet", action="store_true", help="Print only the verdict line")
    ns = parser.parse_args(argv)
    attestation = json.loads(ns.path.read_text())
    result = walk(attestation)
    if ns.quiet:
        print(result["verdict"])
    else:
        print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
