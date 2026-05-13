"""Pydantic schema enforcement tests (R1, R3, R4, R5, R6)."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from meridian.canon.schema import Attestation, Claim, InferenceType


def test_observation_attestation_validates(sample_attestation_dict: dict) -> None:
    attestation = Attestation.model_validate({**sample_attestation_dict, "seal": None})
    assert attestation.attestation_id == sample_attestation_dict["attestation_id"]


def test_r5_non_observational_claim_requires_gap() -> None:
    """R5: induction/deduction/abduction/compound claims MUST declare at least one gap."""
    with pytest.raises(ValidationError):
        Claim(
            claim_id="claim-01-X",
            statement="Empty gaps but inference is deduction",
            supports=["obs-01"],
            inference_type=InferenceType.DEDUCTION,
            gaps=[],
        )


def test_r5_observation_can_have_empty_gaps() -> None:
    """observation-typed claims over verified content hashes may have empty gaps."""
    claim = Claim(
        claim_id="claim-01-X",
        statement="Header literally said 'From: alice'",
        supports=["obs-01"],
        inference_type=InferenceType.OBSERVATION,
        gaps=[],
    )
    assert claim.gaps == []


def test_r3_supports_must_resolve(sample_attestation_dict: dict) -> None:
    """R3: every claim's supports must resolve to a known observation_id or earlier claim_id."""
    bad = copy.deepcopy(sample_attestation_dict)
    bad["findings"]["claims"][0]["supports"] = ["obs-DOES-NOT-EXIST"]
    with pytest.raises(ValidationError):
        Attestation.model_validate({**bad, "seal": None})


def test_r3_forward_reference_prohibited(sample_attestation_dict: dict) -> None:
    """A claim cannot reference a claim_id defined later in the same Findings block."""
    bad = copy.deepcopy(sample_attestation_dict)
    bad["findings"]["claims"] = [
        {
            "claim_id": "claim-FIRST",
            "statement": "References later claim",
            "supports": ["claim-LATER"],
            "inference_type": "deduction",
            "gaps": ["test gap"],
        },
        {
            "claim_id": "claim-LATER",
            "statement": "Defined later",
            "supports": ["obs-01ABCDEFGHJKMNPQRSTVWXYZ01"],
            "inference_type": "observation",
            "gaps": [],
        },
    ]
    with pytest.raises(ValidationError):
        Attestation.model_validate({**bad, "seal": None})


def test_r6_refutation_must_have_challenge(sample_attestation_dict: dict) -> None:
    """R6: refutation block must contain at least one Challenge."""
    bad = copy.deepcopy(sample_attestation_dict)
    bad["refutation"]["challenges"] = []
    with pytest.raises(ValidationError):
        Attestation.model_validate({**bad, "seal": None})


def test_refutation_target_must_resolve(sample_attestation_dict: dict) -> None:
    bad = copy.deepcopy(sample_attestation_dict)
    bad["refutation"]["challenges"][0]["targets"] = ["claim-DOES-NOT-EXIST"]
    with pytest.raises(ValidationError):
        Attestation.model_validate({**bad, "seal": None})


def test_witness_requires_content_retrievability(sample_attestation_dict: dict) -> None:
    """R2: WitnessEntry must have either content_ref or content_inline."""
    bad = copy.deepcopy(sample_attestation_dict)
    bad["witness"][0]["content_ref"] = None
    bad["witness"][0]["content_inline"] = None
    with pytest.raises(ValidationError):
        Attestation.model_validate({**bad, "seal": None})
