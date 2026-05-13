"""Coverage audit: batch-level analysis of un-attacked sub-populations
(paper §6.6.1).

Computes which sub-populations of an enrichment batch received zero or
anomalously low refutation coverage, and emits a list of DeclinedChallenge
entries with machine-readable reasons that populate the Refutation block's
`coverage.declined` array.

This is the Canon specification's required honest-accounting of un-attacked
material. Per R6, every challenge type MUST be either applied to a claim
or declined with a reason; the coverage audit is the enforcement mechanism.

Operates over a batch (list of attestations) rather than per-claim.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Sequence


REASON_BATCH_LEVEL = "applies_at_batch_level_not_per_observation"
REASON_NO_INFERENCE = "no_inferential_findings_to_contest"
REASON_NO_ENTITIES = "no_entity_claims_to_cross_reference"
REASON_NO_INDEX = "no_search_index_available_to_query"
REASON_NO_PROMPT = "original_prompt_unavailable_no_replay_possible"


def coverage_audit(
    attestations: Sequence[dict],
) -> dict:
    """Aggregate coverage statistics across a batch of attestations.

    Returns a partial Challenge dict for the harness; `outcome` is always
    `survived` because the audit is descriptive, not adversarial. The
    interesting payload is in the gaps the harness will record alongside.

    The dict includes a `gaps` field with sub-populations that received
    zero coverage, suitable for populating each enrichment's gaps array.
    """
    if not attestations:
        return {
            "type": "coverage_audit",
            "input": "empty batch; no coverage to audit",
            "outcome": "survived",
            "revisions": None,
            "gaps": [],
        }

    # Aggregate by source kind, by inference type, by claim count.
    by_source: Counter[str] = Counter()
    by_inference: Counter[str] = Counter()
    challenges_applied: Counter[str] = Counter()
    challenges_declined: Counter[str] = Counter()
    decline_reasons: Counter[tuple[str, str]] = Counter()
    total_claims = 0

    for att in attestations:
        # Source taxonomy from the witness URI scheme.
        for w in att.get("witness", []):
            uri = w.get("source", "")
            scheme = uri.split("://", 1)[0] if "://" in uri else "unknown"
            by_source[scheme] += 1

        for c in att.get("findings", {}).get("claims", []):
            total_claims += 1
            by_inference[c.get("inference_type", "unknown")] += 1

        cov = att.get("refutation", {}).get("coverage", {})
        for t in cov.get("applied", []):
            challenges_applied[t] += 1
        for d in cov.get("declined", []):
            t = d.get("type") if isinstance(d, dict) else str(d)
            r = d.get("reason", "") if isinstance(d, dict) else ""
            challenges_declined[t] += 1
            decline_reasons[(t, r)] += 1

    gaps: list[str] = []
    if challenges_declined and not challenges_applied:
        gaps.append(
            "batch had zero applied challenges of any type; "
            "consider whether refutation infrastructure was reachable during emission"
        )

    # Sub-population: any source kind that produced attestations without
    # any successful adversarial-prompt application.
    sources_with_adversarial = set()
    for att in attestations:
        applied = set(att.get("refutation", {}).get("coverage", {}).get("applied", []))
        if "adversarial_prompt" in applied:
            for w in att.get("witness", []):
                uri = w.get("source", "")
                scheme = uri.split("://", 1)[0] if "://" in uri else "unknown"
                sources_with_adversarial.add(scheme)
    sources_without_adversarial = set(by_source) - sources_with_adversarial
    if sources_without_adversarial:
        gaps.append(
            f"source kinds without any adversarial-prompt coverage: "
            f"{sorted(sources_without_adversarial)}"
        )

    return {
        "type": "coverage_audit",
        "input": (
            f"audited {len(attestations)} attestations / {total_claims} claims; "
            f"sources={dict(by_source)}; inference_types={dict(by_inference)}"
        ),
        "outcome": "survived",
        "revisions": None,
        "gaps": gaps,
        "stats": {
            "total_attestations": len(attestations),
            "total_claims": total_claims,
            "by_source": dict(by_source),
            "by_inference": dict(by_inference),
            "challenges_applied": dict(challenges_applied),
            "challenges_declined": dict(challenges_declined),
        },
    }


def declines_for_solo_attestation(
    attestation: dict,
    *,
    have_models: bool,
    have_registry: bool,
    have_search: bool,
    have_replay_prompt: bool,
) -> list[dict]:
    """For a single-Attestation refutation pass, compute the standard set
    of DeclinedChallenge entries based on which dependencies the harness
    has wired up.

    Used by harness.py to populate `coverage.declined` so every emission
    is R6-conformant regardless of how much LM/index infrastructure is
    available at runtime.
    """
    declined: list[dict] = []
    findings = attestation.get("findings", {})
    claims = findings.get("claims", [])
    has_inferential = any(
        c.get("inference_type") not in (None, "observation") for c in claims
    )
    has_entities = any(
        c.get("inference_type") in ("deduction", "induction", "compound") for c in claims
    )

    if not have_models or not has_inferential:
        declined.append({
            "type": "adversarial_prompt",
            "reason": REASON_NO_INFERENCE if not has_inferential else "no_models_configured",
        })
    if not have_registry or not has_entities:
        declined.append({
            "type": "consistency_check",
            "reason": REASON_NO_ENTITIES if not has_entities else "no_entity_registry_available",
        })
    if not have_search or not has_inferential:
        declined.append({
            "type": "counter_evidence",
            "reason": REASON_NO_INDEX if not have_search else REASON_NO_INFERENCE,
        })
    if not have_replay_prompt or not has_inferential:
        declined.append({
            "type": "replay",
            "reason": REASON_NO_PROMPT if not have_replay_prompt else REASON_NO_INFERENCE,
        })
    # coverage_audit always declines at the per-attestation level.
    declined.append({"type": "coverage_audit", "reason": REASON_BATCH_LEVEL})
    return declined
