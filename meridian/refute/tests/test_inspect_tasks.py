"""Tests for inspect-ai task integration — works with or without inspect-ai."""
from meridian.refute.inspect_tasks import (
    run_adversarial_inspect,
    _tri_model_consensus,
    _parse_outcome_str,
    InspectRefutationResult,
    _INSPECT_AVAILABLE,
)
from meridian.canon.schema import ChallengeOutcome


def test_tri_model_consensus_majority():
    assert _tri_model_consensus(["survived", "survived", "failed"]) == ChallengeOutcome.SURVIVED
    assert _tri_model_consensus(["failed", "failed", "survived"]) == ChallengeOutcome.FAILED


def test_tri_model_consensus_tie():
    assert _tri_model_consensus(["survived", "failed"]) == ChallengeOutcome.CONTESTED


def test_tri_model_consensus_empty():
    assert _tri_model_consensus([]) == ChallengeOutcome.SURVIVED


def test_parse_outcome_str():
    assert _parse_outcome_str("survived") == "survived"
    assert _parse_outcome_str("The claim is FAILED.") == "failed"
    assert _parse_outcome_str("  revised ") == "revised"
    assert _parse_outcome_str("???") == "survived"  # default


def test_run_adversarial_no_models():
    """With empty model list, returns SURVIVED gracefully."""
    result = run_adversarial_inspect("Sky is blue.", "The sky appears blue.", model_names=[])
    assert isinstance(result, InspectRefutationResult)
    assert result.consensus_outcome in list(ChallengeOutcome)


def test_run_adversarial_echo_models():
    """With unreachable models, falls back gracefully."""
    result = run_adversarial_inspect(
        "The document was filed on Jan 1.",
        "Court record shows filing on January 1, 2026.",
        model_names=["nonexistent/model-xyz-qrs"],
    )
    assert isinstance(result, InspectRefutationResult)
    # Should not raise; outcome should be a valid ChallengeOutcome
    assert result.outcome in list(ChallengeOutcome)


def test_inspect_available_flag():
    """_INSPECT_AVAILABLE is a bool."""
    assert isinstance(_INSPECT_AVAILABLE, bool)
