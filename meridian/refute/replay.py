"""Replay challenge: deterministic re-execution of the enrichment prompt
(paper §6.6.1).

The enrichment prompt is executed n=3 times at temperature 0. Variance
across runs beyond a token-level Hamming distance threshold produces a
low-confidence annotation in gaps. Replay catches non-determinism
introduced by tokenization or quantization artifacts rather than by the
model itself.

Requires:
- The original enrichment prompt (string).
- An LM adapter to re-run the prompt against.

When either is unavailable, the harness records a decline.
"""

from __future__ import annotations

from typing import Optional

from meridian.canon.schema import ChallengeOutcome
from .lm import LMAdapter


def hamming_token_distance(a: str, b: str) -> int:
    """Count tokens that differ between two whitespace-split strings.

    Uses a simple zip-based comparison; differences in length count as
    differences for every overshooting token.
    """
    a_toks = a.split()
    b_toks = b.split()
    distance = sum(1 for x, y in zip(a_toks, b_toks) if x != y)
    distance += abs(len(a_toks) - len(b_toks))
    return distance


def replay(
    *,
    prompt: Optional[str],
    model: Optional[LMAdapter],
    n_runs: int = 3,
    distance_threshold: int = 5,
    max_tokens: int = 512,
) -> dict:
    """Re-run the prompt n times; flag non-determinism as a gap.

    Returns a partial Challenge dict.
    """
    if prompt is None or model is None:
        # AUDIT-FIX (R2): cannot replay without prompt+model ⇒ ERROR
        # (inconclusive), not SURVIVED. The harness declines on decline_reason.
        return {
            "type": "replay",
            "input": "no prompt or model available; replay deferred",
            "outcome": ChallengeOutcome.ERROR.value,
            "revisions": None,
            "decline_reason": (
                "original_prompt_unavailable" if prompt is None else "no_replay_model_configured"
            ),
        }
    runs: list[str] = []
    for _ in range(n_runs):
        try:
            runs.append(model.complete(prompt, max_tokens=max_tokens, temperature=0.0))
        except Exception as e:
            # AUDIT-FIX (R2): a replay run threw ⇒ inconclusive, not survived.
            return {
                "type": "replay",
                "input": f"replay run failed: {e}",
                "outcome": ChallengeOutcome.ERROR.value,
                "revisions": None,
                "decline_reason": f"replay_run_error_{type(e).__name__}",
            }
    if not runs:
        # AUDIT-FIX (R2): zero successful runs ⇒ inconclusive, not survived.
        return {
            "type": "replay",
            "input": "no successful replay runs produced",
            "outcome": ChallengeOutcome.ERROR.value,
            "revisions": None,
            "decline_reason": "no_replay_runs",
        }
    # Pairwise max distance.
    max_dist = 0
    for i in range(len(runs)):
        for j in range(i + 1, len(runs)):
            d = hamming_token_distance(runs[i], runs[j])
            if d > max_dist:
                max_dist = d

    if max_dist > distance_threshold:
        return {
            "type": "replay",
            "input": f"{n_runs} runs at temperature 0; max pairwise token distance {max_dist}",
            "outcome": ChallengeOutcome.REVISED.value,
            "revisions": [{
                "max_pairwise_token_distance": max_dist,
                "threshold": distance_threshold,
                "n_runs": n_runs,
            }],
        }
    return {
        "type": "replay",
        "input": f"{n_runs} runs at temperature 0; max pairwise token distance {max_dist} ≤ {distance_threshold}",
        "outcome": ChallengeOutcome.SURVIVED.value,
        "revisions": None,
    }
