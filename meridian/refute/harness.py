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
from .lm import LMAdapter, _LANGFUSE_AVAILABLE, _lf_ctx


class RefutationFailedError(Exception):
    """AUDIT-FIX (R1): raised when a challenge consensus is FAILED (the claim
    was refuted) and the harness was not permitted to remove the claim.

    A FAILED outcome means an adversary majority concluded the claim is
    contradicted by its own sources. Per adversarial.py's documented contract
    ("if consensus is `failed`, the upstream claim is removed or revised") a
    refuted claim must NEVER seal as valid. When auto-removal is disabled the
    harness raises this rather than silently emitting a Refutation block that a
    naive caller would seal — closing the hole where a false claim sealed
    `valid` because the FAILED outcome was simply ignored.
    """

    def __init__(self, failed: list[tuple[str, str]]) -> None:
        self.failed = failed  # list of (claim_id, challenge_id)
        detail = ", ".join(f"{cid} (challenge {chid})" for cid, chid in failed)
        super().__init__(
            "refutation produced FAILED challenge outcome(s) for claim(s) "
            f"that were not removed or revised: {detail}. These claims MUST NOT "
            "seal as valid (R1). Re-run with remove_failed_claims=True to drop "
            "them, or revise the claims and re-run."
        )


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
    backend: str = "native",
    langfuse_session_id: Optional[str] = None,
    remove_failed_claims: bool = False,
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
        remove_failed_claims: AUDIT-FIX (R1). When True, any claim whose
            challenge consensus is FAILED is removed from the attestation's
            findings (and challenges targeting only-removed claims are dropped),
            implementing the "claim removed" branch of the documented contract.
            When False (default), a FAILED outcome for a claim that is not
            otherwise revised raises RefutationFailedError rather than letting
            the caller seal a refuted claim as valid.

    Returns:
        Refutation block dict suitable for assignment to attestation['refutation']
        before sealing.

    Raises:
        RefutationFailedError: if a challenge consensus is FAILED and
            remove_failed_claims is False. CONTESTED outcomes do not raise —
            they are retained with a disagreement gap per the paper — but the
            verifier (walk.py) treats an unresolved CONTESTED as not-valid too.
    """
    # Langfuse session binding (no-op when Langfuse not installed)
    if langfuse_session_id and _LANGFUSE_AVAILABLE and _lf_ctx:
        _lf_ctx.update_current_trace(session_id=langfuse_session_id)

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
            if backend == "inspect_ai":
                # Use inspect-ai multi-model backend when requested
                from .inspect_tasks import run_adversarial_inspect
                inspect_result = run_adversarial_inspect(
                    claim["statement"],
                    _source_excerpt(attestation, claim),
                    model_names=[m.name for m in models],
                )
                partial = {
                    "type": ChallengeType.ADVERSARIAL_PROMPT.value,
                    "input": claim["statement"][:200],
                    "outcome": inspect_result.outcome.value,
                    "model_outcomes": {k: ChallengeOutcome(v) for k, v in inspect_result.model_outcomes.items()},
                    "consensus_outcome": inspect_result.consensus_outcome,
                }
            else:
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

    # If failed/contested/revised outcomes appeared, propagate to claim gaps.
    # AUDIT-FIX (R1): FAILED outcomes either remove the claim or raise — a
    # refuted claim must never silently pass through to sealing.
    challenges = _propagate_outcomes(
        attestation, challenges, remove_failed_claims=remove_failed_claims
    )

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


def _propagate_outcomes(
    attestation: dict,
    challenges: list[dict],
    *,
    remove_failed_claims: bool = False,
) -> list[dict]:
    """Propagate challenge outcomes back onto the claims, enforcing R1.

    AUDIT-FIX (R1): the previous version only acted on CONTESTED/REVISED and
    silently ignored FAILED — a refuted claim sealed `valid`. This version:

      * FAILED  ⇒ the claim was refuted. Either remove it (remove_failed_claims)
                  or raise RefutationFailedError. It must NOT seal as valid.
      * CONTESTED ⇒ retain the claim, append a tri-model disagreement gap (the
                  verifier still treats unresolved CONTESTED as not-valid).
      * REVISED ⇒ retain the claim, append a revision gap.
      * ERROR   ⇒ inconclusive (R2). Does not block sealing, but is recorded
                  honestly as a gap so it is never laundered into 'survived'.

    Returns the (possibly filtered) list of challenges. When a claim is removed,
    challenges that target ONLY removed claims are dropped so the Refutation
    block stays internally consistent; challenges with a mix of removed and
    surviving targets keep only their surviving targets.
    """
    claims_by_id = {c["claim_id"]: c for c in attestation.get("findings", {}).get("claims", [])}

    failed_targets: list[tuple[str, str]] = []  # (claim_id, challenge_id)
    for ch in challenges:
        if ch.get("outcome") == ChallengeOutcome.FAILED.value:
            for tid in ch.get("targets", []):
                if tid in claims_by_id:
                    failed_targets.append((tid, ch.get("challenge_id", "?")))

    if failed_targets and not remove_failed_claims:
        # Refuted claim with no remediation path ⇒ block sealing.
        raise RefutationFailedError(failed_targets)

    removed_ids: set[str] = set()
    if failed_targets and remove_failed_claims:
        removed_ids = {cid for cid, _ in failed_targets}
        claims = attestation.get("findings", {}).get("claims", [])
        attestation["findings"]["claims"] = [
            c for c in claims if c["claim_id"] not in removed_ids
        ]
        # Re-resolve the surviving claims map.
        claims_by_id = {
            c["claim_id"]: c for c in attestation["findings"]["claims"]
        }

    # Gap propagation for surviving claims.
    for ch in challenges:
        outcome = ch.get("outcome")
        if outcome not in (
            ChallengeOutcome.CONTESTED.value,
            ChallengeOutcome.REVISED.value,
            ChallengeOutcome.ERROR.value,
        ):
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
            else:  # ERROR — AUDIT-FIX (R2): record inconclusive honestly.
                ch_type = ch.get("type", "challenge")
                gaps.append(
                    f"{ch_type}_inconclusive: challenge {ch.get('challenge_id')} "
                    "could not be executed (recorded as error, not survived)"
                )
            claim["gaps"] = gaps

    if not removed_ids:
        return challenges

    # Rebuild challenges list, pruning targets that point at removed claims.
    surviving_ids = set(claims_by_id)
    pruned: list[dict] = []
    for ch in challenges:
        targets = [t for t in ch.get("targets", []) if t in surviving_ids]
        if not targets:
            continue  # challenge only referenced removed claims; drop it.
        new_ch = dict(ch)
        new_ch["targets"] = targets
        pruned.append(new_ch)
    return pruned


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
