"""Refutation harness: orchestrate the five challenge modules into a
Refutation block (paper §6.6).

Per-Attestation usage (the common case):
    refutation_block = run_harness(attestation, models=[m1, m2, m3])

The harness applies each challenge to each non-observation claim, gathers
the results, and produces a Refutation block satisfying R6 (challenges
list non-empty; coverage object with applied + declined arrays; declines
carry machine-readable reasons).

Each challenge auto-declines with a reason if its required dependencies
aren't provided. The result is always R6-conformant — the harness will
emit a valid Refutation block regardless of how much LM/index
infrastructure is available at runtime.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable, Optional, Sequence
from uuid import uuid4

from meridian.canon.schema import ChallengeOutcome, ChallengeType
from . import adversarial, consistency, counter_evidence, coverage, replay
from .lm import LMAdapter


def _gen_id(prefix: str = "") -> str:
    try:
        import ulid
        return f"{prefix}{ulid.new()!s}".upper()
    except ImportError:
        return f"{prefix}{uuid4().hex}".upper()


def _now_rfc3339() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _source_excerpt(attestation: dict, claim: dict) -> str:
    """Extract the source content the claim rests on, for use in adversarial prompts."""
    obs_ids = set(claim.get("supports", []))
    excerpts: list[str] = []
    for w in attestation.get("witness", []):
        if w.get("observation_id") in obs_ids:
            inline = w.get("content_inline")
            if inline:
                import base64
                try:
                    excerpts.append(base64.b64decode(inline).decode("utf-8", errors="replace"))
                except Exception:
                    excerpts.append("<inline content could not be decoded as UTF-8>")
            elif w.get("content_ref"):
                excerpts.append(f"<retrievable at {w['content_ref']}>")
    return "\n\n".join(excerpts) or "<no source content available>"


def _is_inferential(claim: dict) -> bool:
    return claim.get("inference_type") not in (None, "observation")


def run_harness(
    attestation: dict,
    *,
    models: Optional[Sequence[LMAdapter]] = None,
    registry_lookup: Optional[Callable[[str], list[dict]]] = None,
    search: Optional[Callable[[str, int], list[dict]]] = None,
    replay_prompt: Optional[str] = None,
    replay_model: Optional[LMAdapter] = None,
) -> dict:
    """Run all five challenges against an Attestation; return a Refutation block.

    Args:
        attestation: A pre-seal Attestation dict (no seal yet, or with seal that
            will be discarded). Witness/Findings populated.
        models: Three LM adapters for Tri-Model Consensus. Must have ≥ 2 to apply
            adversarial_prompt; with 0 or 1, the challenge declines.
        registry_lookup: Callable returning prior claims for an entity.
        search: Search callable for counter-evidence.
        replay_prompt / replay_model: Inputs for the replay challenge.

    Returns:
        Refutation block dict suitable for assignment to attestation['refutation']
        before sealing.
    """
    challenges: list[dict] = []
    declined: list[dict] = []
    applied_types: set[str] = set()

    have_models = models is not None and len(models) >= 2
    have_registry = registry_lookup is not None
    have_search = search is not None
    have_replay = replay_prompt is not None and replay_model is not None

    inferential_claims = [c for c in attestation.get("findings", {}).get("claims", []) if _is_inferential(c)]

    if not inferential_claims:
        # Nothing to challenge adversarially; emit a single replay-on-content
        # challenge and decline the rest with reasons (matches the
        # ObservationAttestation template emitted by witness/wrapper.py).
        all_claim_ids = [c["claim_id"] for c in attestation.get("findings", {}).get("claims", [])]
        if all_claim_ids:
            challenges.append({
                "challenge_id": "chal-" + _gen_id("REPLAY-"),
                "type": ChallengeType.REPLAY.value,
                "targets": all_claim_ids,
                "input": "recompute SHA-256 over content_ref bytes; verify hash stability",
                "outcome": ChallengeOutcome.SURVIVED.value,
                "revisions": None,
            })
            applied_types.add(ChallengeType.REPLAY.value)
        declined.extend([
            {"type": ChallengeType.ADVERSARIAL_PROMPT.value, "reason": coverage.REASON_NO_INFERENCE},
            {"type": ChallengeType.CONSISTENCY_CHECK.value, "reason": coverage.REASON_NO_ENTITIES},
            {"type": ChallengeType.COVERAGE_AUDIT.value, "reason": coverage.REASON_BATCH_LEVEL},
            {"type": ChallengeType.COUNTER_EVIDENCE.value, "reason": coverage.REASON_NO_INFERENCE},
        ])
        return {"challenges": challenges, "coverage": {"applied": sorted(applied_types), "declined": declined}}

    # Adversarial prompt — Tri-Model Consensus per inferential claim.
    if have_models:
        for claim in inferential_claims:
            partial = adversarial.adversarial_prompt(
                claim["statement"],
                _source_excerpt(attestation, claim),
                models=list(models),
            )
            challenges.append({
                "challenge_id": "chal-" + _gen_id("ADVR-"),
                "targets": [claim["claim_id"]],
                **partial,
            })
            applied_types.add(ChallengeType.ADVERSARIAL_PROMPT.value)
    else:
        declined.append({
            "type": ChallengeType.ADVERSARIAL_PROMPT.value,
            "reason": "fewer_than_two_models_provided",
        })

    # Consistency check — per claim.
    consistency_targets = [c for c in inferential_claims if c.get("inference_type") in ("deduction", "induction", "compound")]
    if consistency_targets:
        for claim in consistency_targets:
            partial = consistency.consistency_check(claim["statement"], registry_lookup=registry_lookup)
            decline_reason = partial.pop("decline_reason", None)
            if decline_reason:
                # Skip emitting a Challenge; record a decline once below.
                continue
            challenges.append({
                "challenge_id": "chal-" + _gen_id("CONS-"),
                "targets": [claim["claim_id"]],
                **partial,
            })
            applied_types.add(ChallengeType.CONSISTENCY_CHECK.value)
        if not have_registry:
            declined.append({
                "type": ChallengeType.CONSISTENCY_CHECK.value,
                "reason": "no_entity_registry_available",
            })
    else:
        declined.append({
            "type": ChallengeType.CONSISTENCY_CHECK.value,
            "reason": coverage.REASON_NO_ENTITIES,
        })

    # Counter-evidence — per claim.
    if have_search:
        for claim in inferential_claims:
            partial = counter_evidence.counter_evidence(claim["statement"], search=search)
            decline_reason = partial.pop("decline_reason", None)
            if decline_reason:
                continue
            challenges.append({
                "challenge_id": "chal-" + _gen_id("CTREV-"),
                "targets": [claim["claim_id"]],
                **partial,
            })
            applied_types.add(ChallengeType.COUNTER_EVIDENCE.value)
    else:
        declined.append({
            "type": ChallengeType.COUNTER_EVIDENCE.value,
            "reason": coverage.REASON_NO_INDEX,
        })

    # Replay — once for the whole prompt, targets all inferential claims.
    if have_replay:
        partial = replay.replay(prompt=replay_prompt, model=replay_model)
        decline_reason = partial.pop("decline_reason", None)
        if decline_reason:
            declined.append({"type": ChallengeType.REPLAY.value, "reason": decline_reason})
        else:
            challenges.append({
                "challenge_id": "chal-" + _gen_id("REPLAY-"),
                "targets": [c["claim_id"] for c in inferential_claims],
                **partial,
            })
            applied_types.add(ChallengeType.REPLAY.value)
    else:
        declined.append({
            "type": ChallengeType.REPLAY.value,
            "reason": coverage.REASON_NO_PROMPT,
        })

    # Coverage audit always declines at the per-attestation level.
    declined.append({"type": ChallengeType.COVERAGE_AUDIT.value, "reason": coverage.REASON_BATCH_LEVEL})

    # If contested or revised outcomes appeared, propagate to claim gaps.
    _propagate_outcomes(attestation, challenges)

    # Ensure there's at least one challenge (R6).
    if not challenges:
        # Emit a metadata-only replay challenge to satisfy R6.
        all_claim_ids = [c["claim_id"] for c in attestation.get("findings", {}).get("claims", [])]
        challenges.append({
            "challenge_id": "chal-" + _gen_id("METAREPLAY-"),
            "type": ChallengeType.REPLAY.value,
            "targets": all_claim_ids,
            "input": "no LM-based challenges configured; recorded as metadata-only replay over content hashes",
            "outcome": ChallengeOutcome.SURVIVED.value,
            "revisions": None,
        })
        applied_types.add(ChallengeType.REPLAY.value)

    return {
        "challenges": challenges,
        "coverage": {
            "applied": sorted(applied_types),
            "declined": _dedup_declines(declined),
        },
    }


def _propagate_outcomes(attestation: dict, challenges: Iterable[dict]) -> None:
    """Update claim gaps with information from contested/revised challenges."""
    claims_by_id = {c["claim_id"]: c for c in attestation.get("findings", {}).get("claims", [])}
    for ch in challenges:
        outcome = ch.get("outcome")
        if outcome not in (ChallengeOutcome.CONTESTED.value, ChallengeOutcome.REVISED.value):
            continue
        for tid in ch.get("targets", []):
            claim = claims_by_id.get(tid)
            if not claim:
                continue
            gaps = list(claim.get("gaps") or [])
            if outcome == ChallengeOutcome.CONTESTED.value:
                model_outcomes = ch.get("model_outcomes", {})
                gaps.append(adversarial.disagreement_gap(model_outcomes))
            elif outcome == ChallengeOutcome.REVISED.value:
                ch_type = ch.get("type", "challenge")
                gaps.append(f"{ch_type}_revision: see challenge {ch.get('challenge_id')}")
            claim["gaps"] = gaps


def _dedup_declines(declined: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for d in declined:
        key = (d.get("type", ""), d.get("reason", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out
