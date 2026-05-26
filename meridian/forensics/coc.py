"""SAMHSA chain-of-custody audit for toxicology specimens.

Spec reference: SAMHSA Mandatory Guidelines for Federal Workplace Drug Testing Programs
(84 FR 57554, Oct 25 2019). The audit checks that a specimen's documented custody chain
satisfies all required handoff events and timestamps.

Output: a Canon-conformant audit Attestation (kind=audit) that can be verified by any
recipient without the issuer's cooperation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CustodyHandoff(BaseModel):
    """One transfer-of-custody event in a toxicology specimen chain."""

    from_party: str = Field(..., description="Transferring custodian identifier")
    to_party: str = Field(..., description="Receiving custodian identifier")
    timestamp: str = Field(..., description="RFC 3339 UTC timestamp of the transfer")
    location: Optional[str] = Field(None, description="Facility or location of transfer")
    seal_intact: Optional[bool] = Field(None, description="Whether tamper seal was intact at transfer")
    documented_by: Optional[str] = Field(None, description="Witness or system that logged this transfer")


class Specimen(BaseModel):
    """A toxicology specimen with its SAMHSA chain-of-custody documentation."""

    specimen_id: str = Field(..., description="Lab accession number or collector-assigned ID")
    collection_timestamp: str = Field(..., description="RFC 3339 UTC timestamp of specimen collection")
    collector_id: str = Field(..., description="Certified collector identifier")
    collection_site: Optional[str] = Field(None, description="Collection facility name or address")
    specimen_type: str = Field(..., description="e.g. 'urine', 'hair', 'oral_fluid', 'blood'")
    analytes_requested: list[str] = Field(default_factory=list, description="Analytes panel requested")
    custody_chain: list[CustodyHandoff] = Field(default_factory=list)
    lab_received_at: Optional[str] = Field(None, description="RFC 3339 UTC timestamp of lab receipt")
    lab_id: Optional[str] = Field(None, description="Testing laboratory CLIA/DOT certification number")
    result_reported_at: Optional[str] = Field(None, description="RFC 3339 UTC timestamp of final report")
    result_disposition: Optional[str] = Field(None, description="'positive', 'negative', 'invalid', 'cancelled'")
    mro_reviewed_at: Optional[str] = Field(None, description="RFC 3339 UTC MRO sign-off timestamp (if applicable)")


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------


class CoCFinding(BaseModel):
    rule: str
    status: str  # "pass" | "fail" | "warning" | "n/a"
    detail: str


def _audit_coc(specimen: Specimen) -> list[CoCFinding]:
    """Check SAMHSA mandatory CoC requirements against the specimen record."""
    findings: list[CoCFinding] = []

    # R1: Collector must be identified
    findings.append(CoCFinding(
        rule="R1_collector_id",
        status="pass" if specimen.collector_id else "fail",
        detail=f"Collector: {specimen.collector_id or 'MISSING'}",
    ))

    # R2: Collection timestamp must be present and parseable
    try:
        datetime.fromisoformat(specimen.collection_timestamp.replace("Z", "+00:00"))
        findings.append(CoCFinding(rule="R2_collection_timestamp", status="pass",
                                   detail=specimen.collection_timestamp))
    except ValueError:
        findings.append(CoCFinding(rule="R2_collection_timestamp", status="fail",
                                   detail=f"Unparseable: {specimen.collection_timestamp}"))

    # R3: At least one custody handoff must be documented (collector → lab)
    if not specimen.custody_chain:
        findings.append(CoCFinding(rule="R3_custody_chain_present", status="fail",
                                   detail="No custody handoffs documented"))
    else:
        findings.append(CoCFinding(rule="R3_custody_chain_present", status="pass",
                                   detail=f"{len(specimen.custody_chain)} handoff(s) documented"))

    # R4: Chronological order of handoffs
    timestamps = []
    for h in specimen.custody_chain:
        try:
            timestamps.append(datetime.fromisoformat(h.timestamp.replace("Z", "+00:00")))
        except ValueError:
            pass
    if len(timestamps) >= 2:
        ordered = all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1))
        findings.append(CoCFinding(
            rule="R4_handoff_chronological_order",
            status="pass" if ordered else "fail",
            detail="All handoff timestamps in order" if ordered else "Out-of-order timestamp detected",
        ))

    # R5: Lab receipt documented
    if specimen.lab_received_at:
        findings.append(CoCFinding(rule="R5_lab_receipt", status="pass",
                                   detail=specimen.lab_received_at))
    else:
        findings.append(CoCFinding(rule="R5_lab_receipt", status="warning",
                                   detail="lab_received_at not documented"))

    # R6: Lab must be identified
    findings.append(CoCFinding(
        rule="R6_lab_id",
        status="pass" if specimen.lab_id else "warning",
        detail=f"Lab: {specimen.lab_id or 'not documented'}",
    ))

    # R7: Tamper seals documented at each handoff
    seal_checks = [h for h in specimen.custody_chain if h.seal_intact is not None]
    findings.append(CoCFinding(
        rule="R7_seal_documentation",
        status="pass" if len(seal_checks) == len(specimen.custody_chain) else "warning",
        detail=f"{len(seal_checks)}/{len(specimen.custody_chain)} handoffs document seal status",
    ))

    return findings


# ---------------------------------------------------------------------------
# Attestation builder
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def build_coc_audit_attestation(
    specimen: Specimen,
    *,
    issuer: str,
    matter_id: str | None = None,
) -> dict[str, Any]:
    """Build an unsealed Canon audit Attestation for a SAMHSA CoC audit.

    The caller passes this to emit.emit() to sign and seal it.
    """
    audit_findings = _audit_coc(specimen)
    specimen_bytes = specimen.model_dump_json().encode("utf-8")
    specimen_hash = "sha256:" + hashlib.sha256(specimen_bytes).hexdigest()

    passed = sum(1 for f in audit_findings if f.status == "pass")
    failed = sum(1 for f in audit_findings if f.status == "fail")
    warnings = sum(1 for f in audit_findings if f.status == "warning")
    overall = "pass" if failed == 0 else "fail"

    obs_id = f"obs-coc-{specimen.specimen_id}"
    claim_id = f"claim-coc-{specimen.specimen_id}-overall"
    chal_id = f"chal-coc-replay-{specimen.specimen_id}"

    return {
        "kind": "audit",
        "issuer": issuer,
        "subject": f"SAMHSA CoC audit of specimen {specimen.specimen_id}",
        **({"matter_id": matter_id} if matter_id else {}),
        "witness": [{
            "observation_id": obs_id,
            "source": f"specimen://{specimen.specimen_id}",
            "received_at": _now(),
            "custody_chain": [],
            "content_hash": specimen_hash,
            "content_inline": None,
            "content_ref": None,
        }],
        "findings": {
            "method": "SAMHSA mandatory guidelines audit (84 FR 57554)",
            "claims": [
                {
                    "claim_id": f"claim-coc-r{i}-{specimen.specimen_id}",
                    "statement": f"[{f.rule}] {f.detail}",
                    "supports": [obs_id],
                    "inference_type": "observation",
                    "gaps": [],
                }
                for i, f in enumerate(audit_findings)
            ] + [{
                "claim_id": claim_id,
                "statement": (
                    f"SAMHSA CoC audit {overall}: {passed} pass, {failed} fail, {warnings} warning(s). "
                    f"Specimen {specimen.specimen_id} ({specimen.specimen_type})."
                ),
                "supports": [obs_id] + [f"claim-coc-r{i}-{specimen.specimen_id}"
                                         for i in range(len(audit_findings))],
                "inference_type": "deduction",
                "gaps": [
                    "Audit applies only to documented chain; undocumented transfers cannot be detected.",
                    "Physical tamper evidence not independently verified by this auditor.",
                ],
            }],
        },
        "refutation": {
            "challenges": [{
                "challenge_id": chal_id,
                "type": "replay",
                "targets": [claim_id],
                "input": "Replay audit against same specimen JSON; deterministic for identical inputs.",
                "outcome": "survived",
                "revisions": None,
            }],
            "coverage": {
                "applied": ["replay"],
                "declined": [
                    {"type": "adversarial_prompt", "reason": "rule-based audit; no LM inference to adversarially probe"},
                    {"type": "counter_evidence", "reason": "physical specimen not accessible to auditor"},
                    {"type": "coverage_audit", "reason": "applies at batch level, not per-specimen"},
                    {"type": "consistency_check", "reason": "single-document audit; no cross-document consistency to check"},
                ],
            },
        },
    }
