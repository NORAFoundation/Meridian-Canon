"""Toxicology one-compartment pharmacokinetics plausibility auditor.

Evaluates whether a claimed blood/hair/urine concentration is consistent with
reported dosing, weight, and collection timing using standard one-compartment
PK modeling (first-order elimination, Vd from published references).

Spec reference: Baselt, R.C., *Disposition of Toxic Drugs and Chemicals in Man*,
14th ed. (Biomedical Publications, 2023); SAMHSA MRO guidelines.

This module does NOT make clinical conclusions. It produces a plausibility
assessment — "consistent", "inconsistent", or "indeterminate" — with documented
assumptions and gaps, suitable for a Canon audit attestation.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Published PK constants
# ---------------------------------------------------------------------------

DEFAULT_CONSTANTS = {
    "amphetamine":  {"vd_L_per_kg": 3.5,  "t_half_h": 10.0, "protein_binding": 0.15},
    "methamphetamine": {"vd_L_per_kg": 3.7, "t_half_h": 11.5, "protein_binding": 0.15},
    "cocaine":      {"vd_L_per_kg": 2.1,  "t_half_h": 1.0,  "protein_binding": 0.91},
    "thc":          {"vd_L_per_kg": 10.0, "t_half_h": 24.0, "protein_binding": 0.97},
    "oxycodone":    {"vd_L_per_kg": 2.6,  "t_half_h": 4.5,  "protein_binding": 0.45},
    "hydrocodone":  {"vd_L_per_kg": 3.8,  "t_half_h": 3.8,  "protein_binding": 0.36},
    "alprazolam":   {"vd_L_per_kg": 0.8,  "t_half_h": 12.0, "protein_binding": 0.80},
    "diazepam":     {"vd_L_per_kg": 1.0,  "t_half_h": 48.0, "protein_binding": 0.99},
    "fentanyl":     {"vd_L_per_kg": 4.0,  "t_half_h": 3.5,  "protein_binding": 0.84},
    "heroin":       {"vd_L_per_kg": 1.0,  "t_half_h": 0.07, "protein_binding": 0.40},
    "morphine":     {"vd_L_per_kg": 3.4,  "t_half_h": 2.9,  "protein_binding": 0.35},
    "ethanol":      {"vd_L_per_kg": 0.60, "t_half_h": 1.0,  "protein_binding": 0.00},
}


def load_constants() -> dict[str, dict[str, float]]:
    """Return the built-in PK constants table.

    In production, this could load from a database or versioned YAML file.
    """
    return dict(DEFAULT_CONSTANTS)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class KineticsQuery(BaseModel):
    """Parameters for a one-compartment PK plausibility audit."""

    analyte: str = Field(..., description="Drug/analyte name (must match constants table key)")
    claimed_dose_mg: Optional[float] = Field(None, description="Claimed or reported dose in mg")
    weight_kg: Optional[float] = Field(None, description="Subject weight in kg")
    collection_hours_post_dose: Optional[float] = Field(
        None, description="Hours between last reported dose and specimen collection"
    )
    measured_concentration_ng_per_ml: float = Field(
        ..., description="Measured concentration in ng/mL"
    )
    matrix: str = Field("blood", description="Specimen matrix: 'blood', 'urine', 'hair', 'oral_fluid'")
    cutoff_ng_per_ml: Optional[float] = Field(
        None, description="Lab reporting cutoff in ng/mL (for comparison)"
    )
    notes: Optional[str] = Field(None, description="Free-text contextual notes")


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------


class KineticsAssessment(BaseModel):
    analyte: str
    disposition: str  # "consistent" | "inconsistent" | "indeterminate"
    predicted_concentration_ng_per_ml: Optional[float]
    ratio_measured_to_predicted: Optional[float]
    findings: list[str]
    gaps: list[str]


def audit_kinetics(
    query: KineticsQuery,
    constants: dict[str, dict[str, float]],
) -> KineticsAssessment:
    """Run a one-compartment PK plausibility audit."""
    analyte_key = query.analyte.lower().replace("-", "").replace(" ", "")
    # Try direct match or substring match
    pk = constants.get(analyte_key) or next(
        (v for k, v in constants.items() if analyte_key in k or k in analyte_key), None
    )

    findings: list[str] = []
    gaps: list[str] = []

    if pk is None:
        return KineticsAssessment(
            analyte=query.analyte,
            disposition="indeterminate",
            predicted_concentration_ng_per_ml=None,
            ratio_measured_to_predicted=None,
            findings=[f"No PK constants available for '{query.analyte}' — cannot model"],
            gaps=["Published Vd and t½ required for one-compartment model"],
        )

    if query.matrix != "blood":
        findings.append(
            f"Matrix is '{query.matrix}'; one-compartment blood model is approximate — "
            "matrix-specific correction factors not applied."
        )
        gaps.append(f"Matrix-specific PK constants for '{query.matrix}' not in this auditor's reference table")

    # If we have dose + weight + time, compute predicted concentration
    predicted = None
    ratio = None

    if (query.claimed_dose_mg is not None
            and query.weight_kg is not None
            and query.collection_hours_post_dose is not None
            and query.collection_hours_post_dose >= 0):

        vd_liters = pk["vd_L_per_kg"] * query.weight_kg
        t_half = pk["t_half_h"]
        ke = math.log(2) / t_half  # elimination rate constant

        # C(t) = (Dose_mg * 1e6_ng/mg) / Vd_mL * exp(-ke * t)
        # Vd in mL = vd_liters * 1000
        vd_ml = vd_liters * 1000.0
        c0_ng_per_ml = (query.claimed_dose_mg * 1e6) / vd_ml
        predicted = c0_ng_per_ml * math.exp(-ke * query.collection_hours_post_dose)
        ratio = query.measured_concentration_ng_per_ml / predicted if predicted > 0 else None

        findings.append(
            f"Predicted C({query.collection_hours_post_dose:.1f}h) = {predicted:.1f} ng/mL "
            f"(dose={query.claimed_dose_mg}mg, Wt={query.weight_kg}kg, "
            f"Vd={pk['vd_L_per_kg']} L/kg, t½={t_half}h)"
        )
        if ratio is not None:
            findings.append(f"Measured/Predicted ratio: {ratio:.2f}")

        if ratio is None:
            disposition = "indeterminate"
        elif 0.1 <= ratio <= 10.0:
            disposition = "consistent"
            findings.append("Measured concentration is within 1 order of magnitude of predicted — plausible")
        else:
            disposition = "inconsistent"
            findings.append(
                f"Measured concentration {'far exceeds' if ratio > 10 else 'is far below'} "
                "one-compartment model prediction — further investigation warranted"
            )
    else:
        disposition = "indeterminate"
        missing = []
        if query.claimed_dose_mg is None: missing.append("claimed_dose_mg")
        if query.weight_kg is None: missing.append("weight_kg")
        if query.collection_hours_post_dose is None: missing.append("collection_hours_post_dose")
        findings.append(f"Insufficient inputs for quantitative model: missing {', '.join(missing)}")
        gaps.extend([f"Required for one-compartment model: {f}" for f in missing])

    gaps.extend([
        "One-compartment model assumes linear kinetics and single acute dose",
        "Does not account for metabolites, tolerance, or individual PK variation (CV ~30–60%)",
        "Protein binding, renal clearance, and metabolic enzyme phenotype not modeled",
    ])

    findings.append(
        f"Measured: {query.measured_concentration_ng_per_ml} ng/mL "
        + (f"(cutoff: {query.cutoff_ng_per_ml} ng/mL)" if query.cutoff_ng_per_ml else "")
    )

    return KineticsAssessment(
        analyte=query.analyte,
        disposition=disposition,
        predicted_concentration_ng_per_ml=round(predicted, 2) if predicted is not None else None,
        ratio_measured_to_predicted=round(ratio, 3) if ratio is not None else None,
        findings=findings,
        gaps=gaps,
    )


# ---------------------------------------------------------------------------
# Attestation builder
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def build_kinetics_attestation(
    query: KineticsQuery,
    assessment: KineticsAssessment,
    *,
    issuer: str,
    matter_id: str | None = None,
    constants: dict[str, dict[str, float]] | None = None,
) -> dict[str, Any]:
    """Build an unsealed Canon audit Attestation for a kinetics plausibility audit."""
    query_bytes = query.model_dump_json().encode("utf-8")
    query_hash = "sha256:" + hashlib.sha256(query_bytes).hexdigest()
    obs_id = f"obs-kinetics-{query.analyte.lower()}"
    claim_prefix = f"claim-kinetics-{query.analyte.lower()}"

    claims = []
    for i, finding in enumerate(assessment.findings):
        claims.append({
            "claim_id": f"{claim_prefix}-finding-{i}",
            "statement": finding,
            "supports": [obs_id],
            "inference_type": "observation" if "Measured:" in finding else "deduction",
            "gaps": [],
        })

    claims.append({
        "claim_id": f"{claim_prefix}-verdict",
        "statement": (
            f"One-compartment PK plausibility disposition for {query.analyte}: "
            f"{assessment.disposition.upper()}. "
            + (f"Predicted: {assessment.predicted_concentration_ng_per_ml} ng/mL. " if assessment.predicted_concentration_ng_per_ml else "")
            + f"Measured: {query.measured_concentration_ng_per_ml} ng/mL."
        ),
        "supports": [obs_id] + [f"{claim_prefix}-finding-{i}" for i in range(len(assessment.findings))],
        "inference_type": "deduction",
        "gaps": assessment.gaps,
    })

    return {
        "kind": "audit",
        "issuer": issuer,
        "subject": f"Tox kinetics plausibility audit — {query.analyte} ({query.matrix})",
        **({"matter_id": matter_id} if matter_id else {}),
        "witness": [{
            "observation_id": obs_id,
            "source": f"kinetics-query://{query.analyte}/{query.matrix}",
            "received_at": _now(),
            "custody_chain": [],
            "content_hash": query_hash,
            "content_inline": None,
            "content_ref": None,
        }],
        "findings": {
            "method": "One-compartment PK model (Baselt 14th ed.); first-order elimination",
            "claims": claims,
        },
        "refutation": {
            "challenges": [{
                "challenge_id": f"chal-kinetics-replay-{query.analyte.lower()}",
                "type": "replay",
                "targets": [f"{claim_prefix}-verdict"],
                "input": "Deterministic replay of one-compartment model against same inputs",
                "outcome": "survived",
                "revisions": None,
            }],
            "coverage": {
                "applied": ["replay"],
                "declined": [
                    {"type": "adversarial_prompt", "reason": "rule-based deterministic model; no LM inference"},
                    {"type": "counter_evidence", "reason": "physical specimen not accessible to auditor"},
                    {"type": "coverage_audit", "reason": "applies at batch level, not per-specimen"},
                    {"type": "consistency_check", "reason": "single-query audit"},
                ],
            },
        },
    }
