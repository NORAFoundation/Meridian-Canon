"""inspect-ai Task definitions for Canon refutation challenges.

The five Canon challenge types map to inspect-ai Tasks:
  adversarial_prompt  -> Task with multi-model solver + outcome scorer
  consistency_check   -> Task with registry-lookup tool
  counter_evidence    -> Task with search tool
  replay              -> Task with deterministic hash verifier
  coverage_audit      -> batch-level; always declined at per-attestation level

Install: pip install inspect-ai>=0.3

Usage:
    from meridian.refute.inspect_tasks import run_adversarial_inspect
    result = run_adversarial_inspect(claim, source_excerpt, model_names=["ollama/llama3"])
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Sequence

try:
    from inspect_ai import Task, eval as inspect_eval
    from inspect_ai.dataset import Sample
    from inspect_ai.solver import generate
    from inspect_ai.scorer import Score, scorer, accuracy
    from inspect_ai.model import get_model
    _INSPECT_AVAILABLE = True
except ImportError:
    _INSPECT_AVAILABLE = False

from meridian.canon.schema import ChallengeOutcome


@dataclass
class InspectRefutationResult:
    """Result from an inspect-ai refutation run."""
    outcome: ChallengeOutcome
    model_outcomes: dict[str, str]  # model_name -> outcome string
    consensus_outcome: ChallengeOutcome
    log_location: Optional[str] = None  # path to EvalLog JSON


def _parse_outcome_str(text: str) -> str:
    """Normalize model output to one of: survived, failed, revised, error.

    # AUDIT-FIX (R2): unparseable output ⇒ "error" (inconclusive), not
    # "survived". A garbled/empty model reply must not silently clear a claim.
    """
    norm = (text or "").strip().lower()
    for token in norm.split():
        clean = token.strip(".,;:'\"")
        if clean in {"survived", "passed", "supported"}:
            return "survived"
        if clean in {"failed", "refuted", "disproven"}:
            return "failed"
        if clean in {"revised", "modified", "weakened"}:
            return "revised"
    return "error"  # AUDIT-FIX (R2): unparseable ⇒ inconclusive


def _tri_model_consensus(outcomes: list[str]) -> ChallengeOutcome:
    """Majority vote across model outcomes. Ties → CONTESTED.

    # AUDIT-FIX (R2): empty outcome set ⇒ ERROR (no votes ran), not SURVIVED.
    # A claim with zero usable adversary votes has not been cleared.
    """
    if not outcomes:
        return ChallengeOutcome.ERROR
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o] = counts.get(o, 0) + 1
    best_count = max(counts.values())
    winners = [k for k, v in counts.items() if v == best_count]
    if len(winners) > 1:
        return ChallengeOutcome.CONTESTED
    return ChallengeOutcome(winners[0])


def run_adversarial_inspect(
    claim_statement: str,
    source_excerpt: str,
    *,
    model_names: Sequence[str],
) -> InspectRefutationResult:
    """Run adversarial_prompt challenge via inspect-ai multi-model eval.

    Falls back to EchoAdapter behavior if inspect-ai not available.
    """
    if not model_names:
        # AUDIT-FIX (R2): no models ⇒ challenge could not run ⇒ inconclusive.
        return InspectRefutationResult(
            outcome=ChallengeOutcome.ERROR,
            model_outcomes={},
            consensus_outcome=ChallengeOutcome.ERROR,
        )

    if not _INSPECT_AVAILABLE:
        # Graceful degradation: run each model via LiteLLMAdapter if available
        return _fallback_run(claim_statement, source_excerpt, model_names=model_names)

    from inspect_ai.dataset import MemoryDataset

    PROMPT_TEMPLATE = """You are an adversarial reviewer. Attempt to REFUTE the following claim using only the source content shown.

Claim: {claim}

Source excerpt: {source}

Reply with exactly one word: "survived" (claim is supported), "failed" (claim is contradicted), or "revised" (claim could be salvaged with modifications).

Outcome:"""

    prompt = PROMPT_TEMPLATE.format(claim=claim_statement, source=source_excerpt[:3000])

    model_outcomes: dict[str, str] = {}

    for model_name in model_names:
        try:
            model = get_model(model_name)
            dataset = MemoryDataset([Sample(input=prompt, target="survived")])

            @scorer(metrics=[accuracy()])
            def outcome_scorer():
                async def score(state, target):
                    text = state.output.completion
                    outcome = _parse_outcome_str(text)
                    return Score(value=outcome, answer=outcome)
                return score

            result = inspect_eval(
                Task(dataset=dataset, solver=[generate()], scorer=outcome_scorer()),
                model=model,
                display="none",
            )
            if result and result[0].samples:
                raw = result[0].samples[0].output.completion
                model_outcomes[model_name] = _parse_outcome_str(raw)
            else:
                # AUDIT-FIX (R2): empty eval result ⇒ this model produced no
                # usable vote ⇒ error, not survived.
                model_outcomes[model_name] = "error"
        except Exception:
            # AUDIT-FIX (R2): per-model exception ⇒ error, not survived.
            model_outcomes[model_name] = "error"

    outcomes_list = list(model_outcomes.values())
    consensus = _tri_model_consensus(outcomes_list) if outcomes_list else ChallengeOutcome.ERROR

    # Individual outcome: the consensus, unless CONTESTED. A CONTESTED
    # consensus is surfaced as CONTESTED (not laundered into SURVIVED).
    # AUDIT-FIX (R2): previously CONTESTED collapsed to SURVIVED here.
    primary = consensus

    return InspectRefutationResult(
        outcome=primary,
        model_outcomes=model_outcomes,
        consensus_outcome=consensus,
    )


def _fallback_run(
    claim_statement: str,
    source_excerpt: str,
    *,
    model_names: Sequence[str],
) -> InspectRefutationResult:
    """Fallback when inspect-ai not available — uses LiteLLMAdapter directly."""
    try:
        from meridian.refute.lm import LiteLLMAdapter
        model_outcomes: dict[str, str] = {}
        for name in model_names:
            adapter = LiteLLMAdapter(name)
            outcome = adapter.refute(claim_statement, source_excerpt)
            model_outcomes[name] = outcome.value
        outcomes_list = list(model_outcomes.values())
        # AUDIT-FIX (R2): empty/CONTESTED no longer collapse to SURVIVED.
        consensus = _tri_model_consensus(outcomes_list) if outcomes_list else ChallengeOutcome.ERROR
        primary = consensus
        return InspectRefutationResult(
            outcome=primary,
            model_outcomes=model_outcomes,
            consensus_outcome=consensus,
        )
    except Exception:
        # AUDIT-FIX (R2): fallback path failed entirely ⇒ inconclusive.
        return InspectRefutationResult(
            outcome=ChallengeOutcome.ERROR,
            model_outcomes={},
            consensus_outcome=ChallengeOutcome.ERROR,
        )
