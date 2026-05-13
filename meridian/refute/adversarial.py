"""Tri-Model Consensus adversarial refutation (paper §6.6.1, fig. 4).

Each provisional claim is challenged independently by three architecturally-
distinct adversary models. Outcomes are aggregated by majority rule:

    3/3 agree   ⇒ that outcome
    2/3 agree   ⇒ majority outcome
    all differ  ⇒ contested (claim retained with detailed-disagreement gap)

Failures propagate: if consensus is `failed`, the upstream claim is removed
or revised; if `revised`, the adversary's objection is added to the claim's
gaps. Both transformations happen in harness.py; this module is the pure
voting primitive.
"""

from __future__ import annotations

from collections import Counter
from typing import Sequence

from meridian.canon.schema import ChallengeOutcome
from .lm import LMAdapter


def majority_rule(outcomes: Sequence[ChallengeOutcome]) -> ChallengeOutcome:
    """Aggregate per-model outcomes into a consensus.

    Returns the outcome with strict majority support (2-of-3 or all-3),
    else CONTESTED.
    """
    if not outcomes:
        return ChallengeOutcome.CONTESTED
    counts = Counter(outcomes)
    top, top_count = counts.most_common(1)[0]
    if top_count >= 2:
        return top
    return ChallengeOutcome.CONTESTED


def adversarial_prompt(
    claim_statement: str,
    source_excerpt: str,
    *,
    models: Sequence[LMAdapter],
) -> dict:
    """Run a Tri-Model Consensus refutation on a single claim.

    Returns a partial Challenge dict (no `challenge_id` or `targets`; the
    harness fills those in from the upstream claim's identity). Includes
    `model_outcomes` recording each model's vote so verifiers can see the
    raw votes that produced the consensus.
    """
    if not models:
        raise ValueError("Tri-Model Consensus requires at least one model")
    model_outcomes = {model.name: model.refute(claim_statement, source_excerpt) for model in models}
    consensus = majority_rule(list(model_outcomes.values()))
    return {
        "type": "adversarial_prompt",
        "input": (
            "Tri-Model Consensus across "
            + ", ".join(f"{m.name} ({m.family})" for m in models)
            + ": each model was prompted to refute the claim using only the source excerpt."
        ),
        "outcome": consensus.value,
        "revisions": None,
        "model_outcomes": {name: out.value for name, out in model_outcomes.items()},
        "consensus_outcome": consensus.value,
    }


def disagreement_gap(model_outcomes: dict[str, ChallengeOutcome | str]) -> str:
    """Format a machine-readable gap for the contested case."""
    parts = sorted(
        (name, str(o.value if hasattr(o, "value") else o))
        for name, o in model_outcomes.items()
    )
    return "tri_model_disagreement: " + "; ".join(f"{name}={out}" for name, out in parts)
