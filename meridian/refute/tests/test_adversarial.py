"""Tri-Model Consensus voting tests."""

from __future__ import annotations

import pytest

from meridian.canon.schema import ChallengeOutcome
from meridian.refute.adversarial import adversarial_prompt, disagreement_gap, majority_rule
from meridian.refute.lm import EchoAdapter


def test_three_agree() -> None:
    o = ChallengeOutcome.SURVIVED
    assert majority_rule([o, o, o]) is ChallengeOutcome.SURVIVED


def test_two_of_three_majority() -> None:
    s = ChallengeOutcome.SURVIVED
    f = ChallengeOutcome.FAILED
    assert majority_rule([s, s, f]) is ChallengeOutcome.SURVIVED
    assert majority_rule([f, f, s]) is ChallengeOutcome.FAILED


def test_all_disagree_is_contested() -> None:
    assert majority_rule([
        ChallengeOutcome.SURVIVED,
        ChallengeOutcome.FAILED,
        ChallengeOutcome.REVISED,
    ]) is ChallengeOutcome.CONTESTED


def test_empty_is_contested() -> None:
    assert majority_rule([]) is ChallengeOutcome.CONTESTED


def test_adversarial_prompt_emits_model_outcomes() -> None:
    m1 = EchoAdapter(name="echo-1", outcome=ChallengeOutcome.SURVIVED)
    m2 = EchoAdapter(name="echo-2", outcome=ChallengeOutcome.SURVIVED)
    m3 = EchoAdapter(name="echo-3", outcome=ChallengeOutcome.FAILED)

    result = adversarial_prompt("Some claim.", "Some source.", models=[m1, m2, m3])
    assert result["type"] == "adversarial_prompt"
    assert result["outcome"] == "survived"  # 2/3 survived
    assert result["consensus_outcome"] == "survived"
    assert result["model_outcomes"] == {
        "echo-1": "survived",
        "echo-2": "survived",
        "echo-3": "failed",
    }


def test_adversarial_prompt_contested() -> None:
    m1 = EchoAdapter(name="echo-1", outcome=ChallengeOutcome.SURVIVED)
    m2 = EchoAdapter(name="echo-2", outcome=ChallengeOutcome.FAILED)
    m3 = EchoAdapter(name="echo-3", outcome=ChallengeOutcome.REVISED)
    result = adversarial_prompt("Some claim.", "Some source.", models=[m1, m2, m3])
    assert result["consensus_outcome"] == "contested"


def test_no_models_raises() -> None:
    with pytest.raises(ValueError):
        adversarial_prompt("c", "s", models=[])


def test_disagreement_gap_format() -> None:
    gap = disagreement_gap({
        "M_1": ChallengeOutcome.SURVIVED,
        "M_2": ChallengeOutcome.FAILED,
        "M_3": ChallengeOutcome.REVISED,
    })
    assert "M_1=survived" in gap
    assert "M_2=failed" in gap
    assert "tri_model_disagreement" in gap
