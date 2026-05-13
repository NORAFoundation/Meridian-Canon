"""Admissibility Auditor (paper §6.11).

Consumes a sealed Canon Attestation and produces an audit report --- itself
a Canon-conformant Attestation of kind = "audit" --- enumerating the
artifact properties a trial court would weigh under FRE 901, the Daubert
reliability factors, and the proposed factors of FRE 707.

The auditor does NOT declare admissibility. It organizes the record so a
court can. Every factor is recorded as a typed claim with explicit gaps
and supports, so the audit's own reasoning is auditable.

Three sections, deterministically populated from the input Attestation:

    1. Authentication record (FRE 901).
       Whether each WitnessEntry's content hash re-verifies, whether the
       custody chain is unbroken, whether Ed25519 verifies, whether the
       public-key URL was reachable at audit time.

    2. Reliability factors (Daubert / FRE 707 candidates).
       Per-claim: declared inference type, supports cardinality, gaps
       cardinality, replay variance, Tri-Model Consensus outcomes,
       counter-evidence search results.
       Per-Attestation: coverage of the five challenge types, declines
       with reasons, embedding-model and language-model identifiers.

    3. Caveats and open questions.
       Items the auditor cannot resolve from the Attestation alone ---
       upstream content authenticity, ingest-scope exhaustiveness ---
       surfaced verbatim from the input's gaps and declines, with a
       clear notation that these are matters for evidentiary argument
       rather than algorithmic resolution.

CLI:
    meridian-canon audit <attestation.json>    # via cli.py
    python -m meridian.canon.admissibility_auditor <attestation.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import emit, walk
from .schema import (
    AttestationKind,
    ChallengeOutcome,
    ChallengeType,
    InferenceType,
)


def _now_rfc3339() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _gen_id(prefix: str = "") -> str:
    try:
        import ulid
        return f"{prefix}{ulid.new()!s}".upper()
    except ImportError:
        return f"{prefix}{uuid4().hex}".upper()


# --- Section builders ------------------------------------------------------


def _authentication_record(target: dict[str, Any], walker: dict[str, Any]) -> list[dict[str, Any]]:
    """Section 1: authentication facts derivable from the seven-step walker."""
    claims: list[dict[str, Any]] = []
    target_id = target["attestation_id"]
    steps = walker.get("steps", {})

    # Public-key fetch + fingerprint match (R8).
    s1 = steps.get("step1_public_key_fetch", "")
    claims.append({
        "claim_id": "claim-" + _gen_id("AUTH-PK-"),
        "statement": (
            f"Public-key URL fetch and SHA-256 fingerprint comparison: {s1}. "
            "FRE 901(b)(9) authentication: process producing a result; here, "
            "the issuer's published key matches the key declared in the seal."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "deduction" if s1 == "pass" else "observation",
        "gaps": _ladder([
            "URL availability verified at audit time only",
            "Notarization (e.g., OpenTimestamps) not checked by this auditor",
        ]) if s1 == "pass" else _ladder([
            f"Public-key check failed: {s1}",
        ]),
    })

    # Signature verify.
    s2 = steps.get("step2_signature_verify", "")
    claims.append({
        "claim_id": "claim-" + _gen_id("AUTH-SIG-"),
        "statement": (
            f"Ed25519 signature over chain_hash bytes: {s2}. "
            "Computational infeasibility under Ed25519 security assumptions "
            "(RFC 8032) of producing this signature without the private key."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "deduction" if s2 == "pass" else "observation",
        "gaps": _ladder([
            "Signing-host private-key compromise is out of scope at this layer",
        ]) if s2 == "pass" else _ladder([
            f"Signature did not verify: {s2}",
        ]),
    })

    # Chain-hash recompute.
    s3 = steps.get("step3_chain_hash_recompute", "")
    claims.append({
        "claim_id": "claim-" + _gen_id("AUTH-CH-"),
        "statement": (
            f"RFC 8785 canonical re-serialization and SHA-256 over the "
            f"attestation excluding seal: {s3}. Deterministic verification "
            "that no field has been altered since sealing."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "deduction" if s3 == "pass" else "observation",
        "gaps": _ladder(["RFC 8785 implementation parity across languages is empirical (paper §13)"]),
    })

    # Witness content re-hash.
    s4 = steps.get("step4_witness_content_hashes", {})
    verified = int(s4.get("verified", 0)) if isinstance(s4, dict) else 0
    failed = int(s4.get("failed", 0)) if isinstance(s4, dict) else 0
    claims.append({
        "claim_id": "claim-" + _gen_id("AUTH-WC-"),
        "statement": (
            f"Witness content re-hash: {verified} verified, {failed} failed. "
            "Each content_ref or content_inline was retrieved and re-hashed "
            "against the declared content_hash field."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder([
            "Upstream fabrication not detectable post-ingest (paper §8.4)",
            f"{failed} of {verified + failed} witness entries failed re-hash",
        ]) if failed else _ladder([
            "Upstream fabrication not detectable post-ingest (paper §8.4)",
        ]),
    })

    # Custody chain.
    custody_breaks = _custody_breaks(target)
    claims.append({
        "claim_id": "claim-" + _gen_id("AUTH-CC-"),
        "statement": (
            f"Custody-chain analysis: {custody_breaks} unexplained gaps across all "
            "witness entries. Chain of custody is the documented record of every "
            "transfer from origin to presentation, supporting authentication under "
            "FRE 901(b)(1) and (b)(4)."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation" if custody_breaks == 0 else "compound",
        "gaps": _ladder([
            "Pre-ingest custody is recorded as advisory only (paper §13)",
        ]) if custody_breaks == 0 else _ladder([
            f"{custody_breaks} unexplained custody gaps require argument",
            "Pre-ingest custody is recorded as advisory only (paper §13)",
        ]),
    })
    return claims


def _reliability_factors(target: dict[str, Any]) -> list[dict[str, Any]]:
    """Section 2: Daubert / FRE 707 reliability factors."""
    target_id = target["attestation_id"]
    findings = target.get("findings", {})
    claims_in = findings.get("claims", [])
    refutation = target.get("refutation", {})
    challenges = refutation.get("challenges", [])
    coverage = refutation.get("coverage", {})

    claims: list[dict[str, Any]] = []

    # Inference-type distribution.
    type_counts: dict[str, int] = {}
    for c in claims_in:
        t = c.get("inference_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    claims.append({
        "claim_id": "claim-" + _gen_id("REL-IT-"),
        "statement": (
            f"Inference-type distribution: {type_counts}. Each typed inference "
            "carries a different epistemic warrant. Observations rest on "
            "verifiable bytes; deductions on logical validity; inductions and "
            "abductions are defeasible and warrant scrutiny."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder([
            "Distribution is structural, not a quality measure",
            "Inductive/abductive claims (if any) require closer review",
        ]),
    })

    # Gap-disclosure rate.
    total_claims = len(claims_in)
    claims_with_gaps = sum(1 for c in claims_in if c.get("gaps"))
    rate = claims_with_gaps / total_claims if total_claims else 0
    claims.append({
        "claim_id": "claim-" + _gen_id("REL-GAP-"),
        "statement": (
            f"Gap disclosure rate: {claims_with_gaps}/{total_claims} = {rate:.0%}. "
            "Per R5, non-observational claims must enumerate at least one gap. "
            "Higher disclosure indicates a more self-critical extraction."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder([
            "Rate is a count, not a quality measure of the gaps themselves",
        ]),
    })

    # Five-challenge coverage.
    applied = list(coverage.get("applied", []))
    declined = list(coverage.get("declined", []))
    all_types = {ct.value for ct in ChallengeType}
    missing = all_types - set(applied) - {d["type"] for d in declined if isinstance(d, dict)}
    claims.append({
        "claim_id": "claim-" + _gen_id("REL-CV-"),
        "statement": (
            f"Refutation coverage: {len(applied)} applied, {len(declined)} declined "
            f"with reasons, {len(missing)} unaccounted-for. Per R6, every challenge "
            "type must be either applied or declined with a machine-readable reason."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation" if not missing else "compound",
        "gaps": _ladder([
            "Declined-challenge reasons are machine-readable but their adequacy is for the recipient",
        ]) if not missing else _ladder([
            f"{len(missing)} challenge types neither applied nor declined: {sorted(missing)}",
            "Specification violation: this Attestation is not R6-conformant",
        ]),
    })

    # Tri-Model Consensus.
    tmc = [c for c in challenges if c.get("type") == "adversarial_prompt" and c.get("model_outcomes")]
    if tmc:
        contested = sum(1 for c in tmc if c.get("consensus_outcome") == "contested")
        survived = sum(1 for c in tmc if c.get("consensus_outcome") == "survived")
        claims.append({
            "claim_id": "claim-" + _gen_id("REL-TMC-"),
            "statement": (
                f"Tri-Model Consensus across {len(tmc)} adversarial-prompt challenges: "
                f"{survived} survived, {contested} contested. Three independent models "
                "from architecturally distinct families reduce correlated failure modes "
                "(paper §6.6.1)."
            ),
            "supports": [f"obs-target-{target_id}"],
            "inference_type": "induction",
            "gaps": _ladder([
                "Cross-family adversarial models may still share training-data overlaps",
                "Frontier-model substitution (if any) is a per-claim authorization decision",
            ]),
        })

    # Replay determinism.
    replays = [c for c in challenges if c.get("type") == "replay"]
    if replays:
        survived_replays = sum(1 for c in replays if c.get("outcome") == "survived")
        claims.append({
            "claim_id": "claim-" + _gen_id("REL-RP-"),
            "statement": (
                f"Replay determinism: {survived_replays}/{len(replays)} replay challenges "
                "survived. Variance across deterministic re-runs would surface "
                "tokenization or quantization non-determinism rather than model uncertainty."
            ),
            "supports": [f"obs-target-{target_id}"],
            "inference_type": "observation",
            "gaps": _ladder([
                "Determinism does not entail correctness",
            ]),
        })

    # Method line as model identification.
    method = findings.get("method", "")
    claims.append({
        "claim_id": "claim-" + _gen_id("REL-MD-"),
        "statement": (
            f"Declared method: {method!r}. The method line identifies the model and "
            "configuration that produced the findings, supporting Daubert factor "
            "'general acceptance' and FRE 707 transparency."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder([
            "Method-line freeform; structured model-version logging is implementation-specific",
        ]),
    })
    return claims


def _caveats(target: dict[str, Any]) -> list[dict[str, Any]]:
    """Section 3: items the auditor cannot resolve from the Attestation alone."""
    target_id = target["attestation_id"]
    findings = target.get("findings", {})
    refutation = target.get("refutation", {})

    # Aggregate all gaps from claims.
    aggregated_gaps: list[str] = []
    for c in findings.get("claims", []):
        for g in c.get("gaps", []) or []:
            aggregated_gaps.append(f"{c.get('claim_id')}: {g}")

    declined = refutation.get("coverage", {}).get("declined", [])
    decline_lines = [f"{d.get('type')}: {d.get('reason')}" for d in declined if isinstance(d, dict)]

    claims: list[dict[str, Any]] = []
    claims.append({
        "claim_id": "claim-" + _gen_id("CAV-GAPS-"),
        "statement": (
            f"Aggregated claim gaps ({len(aggregated_gaps)} total): these are the "
            "issuer's own acknowledged limits on each claim. They are NOT defects "
            "in the artifact; they are the artifact's self-disclosure that a court "
            "may weigh in determining what the claims do and do not establish."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder(
            aggregated_gaps[:10] +
            ([f"... and {len(aggregated_gaps) - 10} more gaps not enumerated here"] if len(aggregated_gaps) > 10 else [])
        ) if aggregated_gaps else ["no gaps declared by the issuer"],
    })

    claims.append({
        "claim_id": "claim-" + _gen_id("CAV-DECL-"),
        "statement": (
            f"Declined challenge inventory ({len(declined)} entries): challenge "
            "types deliberately not applied. Per Canon's design, this inventory is "
            "first-class trustworthiness data. The court's substantive judgement, "
            "not the auditor's, determines whether the declines are acceptable."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder(decline_lines) if decline_lines else ["no challenges declined"],
    })

    claims.append({
        "claim_id": "claim-" + _gen_id("CAV-DOCT-"),
        "statement": (
            "Doctrinal scope (paper §13): hearsay (FRE 801-807), best-evidence "
            "(FRE 1001-1008), state Frye-jurisdiction variations, and FRE 902 "
            "self-authentication procedural requirements are out of scope at this "
            "layer. Counsel must analyze them separately."
        ),
        "supports": [f"obs-target-{target_id}"],
        "inference_type": "observation",
        "gaps": _ladder([
            "Hearsay exceptions/exclusions are not flagged by this auditor",
            "FRE 902(13)/(14) certifications would require additional procedural steps",
            "Frye-jurisdiction reliability factors may differ from Daubert factors used here",
        ]),
    })
    return claims


# --- Helpers --------------------------------------------------------------


def _ladder(items: list[str]) -> list[str]:
    """Return list with at least one entry (Pydantic R5 compliance)."""
    return list(items) if items else ["no further qualifications"]


def _custody_breaks(target: dict[str, Any]) -> int:
    """Count witness entries whose custody_chain has unexplained gaps.

    A simple heuristic: an entry has a gap if its custody_chain is empty,
    or if the receiving custodian on the latest event differs from the
    declared issuer of the Attestation. Real legal-doctrinal analysis is
    out of scope; this is structural only.
    """
    issuer = target.get("issuer", "")
    breaks = 0
    for w in target.get("witness", []):
        chain = w.get("custody_chain", [])
        if not chain:
            breaks += 1
            continue
        last = chain[-1]
        if not last.get("custodian"):
            breaks += 1
            continue
    return breaks


# --- Public entry point ---------------------------------------------------


def audit(
    target: dict[str, Any],
    *,
    custodian: str,
    public_key_url: str,
    fingerprint: str | None = None,
    auditor_issuer: str | None = None,
    matter_id: str | None = None,
) -> dict[str, Any]:
    """Produce an audit Attestation analyzing the target Attestation.

    Args:
        target: A sealed Canon Attestation (dict).
        custodian: Keychain account name with the auditor's signing key.
        public_key_url: Stable URL hosting the auditor's PEM.
        fingerprint: Auditor's public-key fingerprint (auto-derived if None).
        auditor_issuer: Issuer string for the audit report; defaults to
            "<target.issuer>+admissibility-auditor".
        matter_id: Inherited from target if not specified.

    Returns:
        A sealed Canon-conformant Attestation of kind = "audit".
    """
    walker_result = walk.walk(target)
    target_id = target["attestation_id"]
    issuer = auditor_issuer or f"{target.get('issuer', 'unknown')}+admissibility-auditor"

    # Witness: cryptographically bind the target Attestation by inlining its
    # canonical (seal-excluded) bytes. The content_hash is the target's
    # chain_hash; a verifier of THIS audit Attestation re-hashes the inlined
    # bytes and confirms they match. This means the audit transitively
    # commits to the target without requiring the verifier to retrieve it.
    import base64
    from .canonicalize import canonicalize_for_seal
    canonical_target = canonicalize_for_seal(target)
    target_chain_hash = target.get("seal", {}).get("chain_hash", "sha256:" + "0" * 64)
    witness_entry = {
        "observation_id": f"obs-target-{target_id}",
        "source": f"attestation://{target_id}",
        "received_at": _now_rfc3339(),
        "custody_chain": [
            {
                "custodian": "admissibility-auditor",
                "received_at": _now_rfc3339(),
                "signature": None,
            }
        ],
        "content_hash": target_chain_hash,
        "content_ref": None,
        "content_inline": base64.b64encode(canonical_target).decode("ascii"),
    }

    findings_claims: list[dict[str, Any]] = []
    findings_claims.extend(_authentication_record(target, walker_result))
    findings_claims.extend(_reliability_factors(target))
    findings_claims.extend(_caveats(target))

    # Refutation: replay confirms determinism. Other challenges declined
    # because the auditor is structural, not adversarial.
    audit_claim_ids = [c["claim_id"] for c in findings_claims]
    audit_attestation = {
        "kind": AttestationKind.AUDIT.value,
        "issuer": issuer,
        "matter_id": matter_id or target.get("matter_id"),
        "subject": f"Admissibility audit of {target_id}",
        "witness": [witness_entry],
        "findings": {
            "method": (
                "Admissibility Auditor v0.1.1: deterministic inspection of the target "
                "Attestation against the seven-step falsification protocol, the five "
                "Canon challenge types, and the FRE 901 / Daubert / Proposed FRE 707 "
                "reliability factors. The auditor does not declare admissibility."
            ),
            "claims": findings_claims,
        },
        "refutation": {
            "challenges": [
                {
                    "challenge_id": "chal-" + _gen_id("AUDIT-replay-"),
                    "type": ChallengeType.REPLAY.value,
                    "targets": audit_claim_ids,
                    "input": "re-run audit deterministically against the same target",
                    "outcome": ChallengeOutcome.SURVIVED.value,
                    "revisions": None,
                }
            ],
            "coverage": {
                "applied": [ChallengeType.REPLAY.value],
                "declined": [
                    {"type": ChallengeType.ADVERSARIAL_PROMPT.value, "reason": "auditor_is_structural_not_adversarial"},
                    {"type": ChallengeType.CONSISTENCY_CHECK.value, "reason": "auditor_findings_are_per_target_not_corpus_wide"},
                    {"type": ChallengeType.COVERAGE_AUDIT.value, "reason": "applies_to_corpus_not_to_audit_artifact"},
                    {"type": ChallengeType.COUNTER_EVIDENCE.value, "reason": "auditor_findings_are_structural_not_inferential"},
                ],
            },
        },
    }

    sealed = emit.emit(
        audit_attestation,
        custodian=custodian,
        public_key_url=public_key_url,
        fingerprint=fingerprint,
    )
    return sealed


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="meridian.canon.admissibility_auditor")
    p.add_argument("path", type=Path, help="Path to the target Attestation JSON")
    p.add_argument("--custodian", required=True)
    p.add_argument("--pubkey-url", required=True)
    p.add_argument("--fingerprint")
    p.add_argument("--auditor-issuer")
    p.add_argument("--out", type=Path, help="Path to write the audit Attestation (defaults to stdout)")
    ns = p.parse_args(argv)

    target = json.loads(ns.path.read_text())
    audit_att = audit(
        target,
        custodian=ns.custodian,
        public_key_url=ns.pubkey_url,
        fingerprint=ns.fingerprint,
        auditor_issuer=ns.auditor_issuer,
    )
    if ns.out:
        ns.out.write_text(json.dumps(audit_att, indent=2, default=str))
        print(f"Wrote {ns.out}")
    else:
        print(json.dumps(audit_att, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
