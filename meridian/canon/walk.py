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

# AUDIT-FIX (K2#1): out-of-band pinned trust is now AVAILABLE via the
# `trust_anchor` parameter on walk()/walk_dsse(). When a trust_anchor is
# supplied, step 1 compares the fetched key's fingerprint against the
# OUT-OF-BAND pinned value (string or {issuer_or_url: fingerprint} map),
# defeating the URL-substitution forgery in which an attacker controls
# public_key_url and writes a self-consistent in-band fingerprint. When no
# trust_anchor is supplied, step 1 falls back to the in-band fingerprint and
# the verdict carries an explicit `trust_warning` flag so callers cannot
# mistake INTEGRITY for AUTHENTICITY.
#
# AUDIT-TODO (K2 — REMAINING, K2#2/K2#3, not built here):
#   K2#2 — transparency-log-backed verification: require a Rekor (or
#          equivalent) inclusion proof for the signature/key so that issuance
#          is publicly logged and append-only, and a hidden second signing is
#          detectable. This removes the need to pin every issuer manually.
#   K2#3 — full key transparency: CT-style monitored log of issuer keys with
#          rotation + revocation semantics, so pinning can be replaced by a
#          monitored gossiped log rather than a static checked-in allowlist.
# Until K2#2/K2#3 land, pinning (K2#1) is the trust anchor; without a pin,
# walk() verifies INTEGRITY, not AUTHENTICITY.

# Machine-readable flag emitted when no out-of-band trust anchor is provided.
TRUST_WARNING = (
    "key trust is in-band only — issuer self-certified; "
    "provide trust_anchor to verify authenticity"
)


def _resolve_trust_anchor(
    trust_anchor: str | dict[str, str] | None,
    *,
    issuer: str | None,
    url: str | None,
) -> str | None:
    """Resolve the OUT-OF-BAND expected fingerprint for this attestation.

    `trust_anchor` is either:
      * a fingerprint string  -> the pinned value applies directly, or
      * a mapping {issuer_id_or_url: fingerprint} -> look up by the
        attestation's public_key_url first, then its issuer id.

    Returns the pinned fingerprint string, or None if no anchor was supplied
    or the mapping has no entry for this issuer/url (caller treats a supplied
    mapping with no match as "not trusted").
    """
    if trust_anchor is None:
        return None
    if isinstance(trust_anchor, str):
        return trust_anchor
    # mapping form: prefer URL match, fall back to issuer id.
    if url is not None and url in trust_anchor:
        return trust_anchor[url]
    if issuer is not None and issuer in trust_anchor:
        return trust_anchor[issuer]
    return None


def _fetch_pem(url: str) -> bytes:
    """Fetch raw PEM bytes from a public_key_url (supports file:// for tests)."""
    if url.startswith("file://"):
        return Path(url.removeprefix("file://")).read_bytes()
    with urlopen(url, timeout=10) as resp:
        return resp.read()


def _check_pinned_fingerprint(
    actual: str,
    trust_anchor: str | dict[str, str] | None,
    *,
    issuer: str | None,
    url: str | None,
) -> str | None:
    """Compare a fetched key's fingerprint against the out-of-band pin.

    Returns None when the key is trusted (or no anchor is in effect for this
    issuer in the string case), or a "fail: step1_key_not_trusted: ..." reason
    string when a pin is in effect and does not match.

    Note: when a *mapping* trust_anchor is supplied but contains no entry for
    this issuer/url, the key is NOT trusted (fail closed) — the operator
    supplied a trust store and this issuer is simply not in it.
    """
    if trust_anchor is None:
        return None
    expected = _resolve_trust_anchor(trust_anchor, issuer=issuer, url=url)
    if expected is None:
        # A mapping was supplied but has no pin for this issuer/url: fail closed.
        return (
            "fail: step1_key_not_trusted: no pinned fingerprint for issuer "
            f"{issuer!r} / url {url!r} in supplied trust store"
        )
    if actual != expected:
        return (
            f"fail: step1_key_not_trusted: fetched key fingerprint {actual} "
            f"does not match pinned {expected}"
        )
    return None


def _step1_public_key_fetch(
    seal: dict[str, Any],
    *,
    trust_anchor: str | dict[str, str] | None = None,
    issuer: str | None = None,
) -> tuple[str, bytes | None]:
    """Fetch PEM from public_key_url and verify its SHA-256 fingerprint.

    When `trust_anchor` is provided, the fetched key's fingerprint is compared
    against the OUT-OF-BAND pinned value (K2#1) — NOT the in-band
    `public_key_fingerprint` the issuer wrote into the seal. This defeats the
    URL-substitution forgery. When `trust_anchor` is None, the in-band
    fingerprint is used (integrity only); the caller attaches `trust_warning`.
    """
    url = seal["public_key_url"]
    declared = seal["public_key_fingerprint"]
    try:
        pem = _fetch_pem(url)
    except Exception as e:
        return f"fail: cannot fetch {url}: {e}", None
    actual = f"sha256:{sha256_hex(pem)}"

    if trust_anchor is not None:
        # Out-of-band pinned trust: compare against the pin, not the in-band value.
        reason = _check_pinned_fingerprint(
            actual, trust_anchor, issuer=issuer, url=url
        )
        if reason is not None:
            return reason, None
        return "pass", pem

    # No anchor: in-band self-certification only (INTEGRITY, not AUTHENTICITY).
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


def _step6b_challenge_outcomes(attestation: dict[str, Any]) -> str:
    """AUDIT-FIX (R3): a sealed Attestation MUST NOT carry an unresolved
    FAILED (refuted) or CONTESTED (tri-model disagreement) challenge outcome.

    Previously the verifier excluded the refutation block's *outcomes* from
    the validity verdict entirely — it only checked that challenge *targets*
    resolved (step 6). That meant an attestation whose own refutation recorded
    that a claim FAILED could still walk to `valid`, exactly the silent-seal
    hole. This step makes the third-party verifier actually check what the
    refutation recorded.

    Semantics (coordinated with the harness):
      * FAILED    ⇒ the claim was refuted; it must have been removed or revised
                    before sealing. Its presence here means the seal is unsound.
      * CONTESTED ⇒ unresolved tri-model disagreement; not cleared. The claim
                    may only seal if it carried a disagreement gap AND the
                    issuer chose to retain it — but a verifier cannot treat an
                    open contest as 'valid' without the recipient's judgment,
                    so we fail closed.
      * ERROR     ⇒ inconclusive (R2). Does NOT fail validity (the challenge
                    simply could not run), but is surfaced informationally.

    Returns "pass" or a "fail: ..." string.
    """
    offending: list[str] = []
    for ch in attestation.get("refutation", {}).get("challenges", []):
        # Prefer consensus_outcome when present (tri-model), else outcome.
        outcome = ch.get("consensus_outcome") or ch.get("outcome")
        if outcome == "failed":
            offending.append(
                f"{ch.get('challenge_id')} (FAILED targets {ch.get('targets')})"
            )
        elif outcome == "contested":
            offending.append(
                f"{ch.get('challenge_id')} (CONTESTED targets {ch.get('targets')})"
            )
    if offending:
        return (
            "fail: sealed attestation carries unresolved refuted/contested "
            f"challenge outcome(s): {'; '.join(offending)} — a refuted claim "
            "must not seal as valid (R3)"
        )
    return "pass"


def _step7_coverage_assessment(attestation: dict[str, Any]) -> str:
    """Informational only (paper §8.3): surfaces declined-challenge inventory.

    Canon requires that the inventory be present, not that the recipient
    finds the declines acceptable. Recipients must judge.
    """
    cov = attestation.get("refutation", {}).get("coverage", {})
    declined = cov.get("declined", [])
    return f"informational: {len(declined)} declined challenge type(s)"


def walk_dsse(
    envelope: dict[str, Any],
    *,
    trust_anchor: str | dict[str, str] | None = None,
) -> dict[str, Any]:
    """Walk a v0.2.0 DSSE envelope. Returns a verdict dict (same shape as walk()).

    `trust_anchor` (K2#1): an OUT-OF-BAND pinned fingerprint string, or a
    {issuer_or_url: fingerprint} mapping. When supplied, step 1 compares the
    fetched key's fingerprint against the pin (NOT the in-band keyid), defeating
    URL substitution. When omitted, the verdict carries `trust_warning`.
    """
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

    # Resolve the issuer id from the payload (for mapping-form trust anchors).
    # Best-effort: the inner attestation is parsed below, but we need the issuer
    # before the step-1 trust check, so peek at it here.
    dsse_issuer: str | None = None
    try:
        _peek = json.loads(_base64.b64decode(envelope["payload"]))
        if isinstance(_peek, dict):
            dsse_issuer = _peek.get("issuer")
    except Exception:
        dsse_issuer = None

    # Step 1: public key fetch + fingerprint check
    try:
        pem = _fetch_pem(url)
    except Exception as e:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step1_public_key_fetch": f"fail: {e}"}}

    actual_fingerprint = f"sha256:{sha256_hex(pem)}"

    if trust_anchor is not None:
        # Out-of-band pinned trust: compare against the pin, not the in-band keyid.
        _reason = _check_pinned_fingerprint(
            actual_fingerprint, trust_anchor, issuer=dsse_issuer, url=url
        )
        s1 = _reason if _reason is not None else "pass"
        if _reason is not None:
            pem = None  # type: ignore[assignment]
    elif actual_fingerprint != keyid:
        s1 = f"fail: fingerprint mismatch (got {actual_fingerprint}, declared {keyid})"
    else:
        s1 = "pass"

    if pem is None:
        return {"verdict": "invalid", "canon_version": "0.2.0", "attestation_id": None,
                "steps": {"step1_public_key_fetch": s1, "step2_dsse_signature": "fail: no public key"}}

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
    s6b = _step6b_challenge_outcomes(inner)  # AUDIT-FIX (R3)
    s7 = _step7_coverage_assessment(inner)

    binary_steps = [s1, s2, s3, s5, s6, s6b]
    valid = all(s == "pass" for s in binary_steps) and s4["failed"] == 0

    result = {
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
            "step6b_challenge_outcomes": s6b,
            "step7_coverage_assessment": s7,
        },
        # K2#1: explicit authenticity provenance for the verdict.
        "trust_basis": "pinned" if trust_anchor is not None else "in-band",
    }
    if trust_anchor is None:
        result["trust_warning"] = TRUST_WARNING
    return result


def walk(
    attestation: dict[str, Any],
    *,
    trust_anchor: str | dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run the seven-step falsification protocol. Returns a verdict dict.

    Accepts both inline-seal (v0.1.x) Attestations and v0.2.0 DSSE envelopes.
    DSSE envelopes are detected by the presence of a top-level `payload` field.

    Trust (K2#1):
      `trust_anchor` is the OUT-OF-BAND authenticity anchor. It is EITHER:
        * a fingerprint string (the issuer's pinned key SHA-256), OR
        * a mapping {issuer_id_or_url: fingerprint} (a trust store; see
          `keys.load_trust_store`).
      When supplied, step 1 compares the FETCHED key's fingerprint against the
      pinned value rather than the in-band `public_key_fingerprint`, defeating
      the URL-substitution forgery (whoever controls public_key_url cannot serve
      their own key and a matching in-band fingerprint to pass verification).
      When omitted, behavior is unchanged BUT the result carries an explicit,
      machine-readable `trust_warning` and `trust_basis: "in-band"` so callers
      cannot mistake INTEGRITY for AUTHENTICITY.
    """
    # Dispatch: DSSE envelope vs inline-seal Attestation
    if "payload" in attestation and "payload_type" in attestation:
        return walk_dsse(attestation, trust_anchor=trust_anchor)

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

    s1_msg, pem = _step1_public_key_fetch(
        seal, trust_anchor=trust_anchor, issuer=attestation.get("issuer")
    )
    s2 = _step2_signature_verify(pem, seal) if pem else "fail: no public key"
    s3 = _step3_chain_hash_recompute(attestation)
    s4 = _step4_witness_content_hashes(attestation)
    s5 = _step5_supports_resolution(attestation)
    s6 = _step6_refutation_targets(attestation)
    s6b = _step6b_challenge_outcomes(attestation)  # AUDIT-FIX (R3)
    s7 = _step7_coverage_assessment(attestation)

    binary_steps = [s1_msg, s2, s3, s5, s6, s6b]
    valid = all(s == "pass" for s in binary_steps) and s4["failed"] == 0

    result = {
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
            "step6b_challenge_outcomes": s6b,
            "step7_coverage_assessment": s7,
        },
        # K2#1: explicit authenticity provenance for the verdict.
        "trust_basis": "pinned" if trust_anchor is not None else "in-band",
    }
    if trust_anchor is None:
        result["trust_warning"] = TRUST_WARNING
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="meridian.canon.walk")
    parser.add_argument("path", type=Path, help="Path to the Attestation JSON")
    parser.add_argument("--quiet", action="store_true", help="Print only the verdict line")
    parser.add_argument(
        "--trust-anchor",
        metavar="FINGERPRINT",
        help="Out-of-band pinned issuer key fingerprint (sha256:<hex>) for K2#1 "
             "authenticity verification.",
    )
    parser.add_argument(
        "--trust-store",
        type=Path,
        metavar="PATH",
        help="Path to a JSON trust store mapping issuer/url -> fingerprint "
             "(takes precedence over --trust-anchor).",
    )
    ns = parser.parse_args(argv)
    attestation = json.loads(ns.path.read_text())
    trust_anchor: str | dict[str, str] | None = None
    if ns.trust_store is not None:
        from .keys import load_trust_store
        trust_anchor = load_trust_store(ns.trust_store)
    elif ns.trust_anchor is not None:
        trust_anchor = ns.trust_anchor
    result = walk(attestation, trust_anchor=trust_anchor)
    if ns.quiet:
        print(result["verdict"])
    else:
        print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
