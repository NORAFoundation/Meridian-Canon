"""Consistency check: cross-claim entity reconciliation (paper §6.6.1).

Claims introducing named persons, dates, or amounts are cross-referenced
against prior claims about the same entities in the corpus. Contradictions
produce a `revised` outcome; consistent claims `survive`.

This module is pure Python — no LM dependency. The entity registry is
expected from the L3 normalization layer (Time-Aware Relationship Graph,
paper §6.4.1) and passed in as a callable.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from meridian.canon.schema import ChallengeOutcome


# Heuristic entity patterns. Production callers should pass a richer
# extractor; this is a fallback when none is provided.
_PHONE_RE = re.compile(r"\+?\d[\d\s().\-]{8,}\d")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_DATE_ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_AMOUNT_USD_RE = re.compile(r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?")


def _extract_entities(text: str) -> list[str]:
    """Default entity extractor: phones, emails, ISO dates, USD amounts.

    Real corpora use a smarter L3 extractor; this provides a sensible
    baseline so the harness can run without one.
    """
    found: list[str] = []
    for pattern in (_PHONE_RE, _EMAIL_RE, _DATE_ISO_RE, _AMOUNT_USD_RE):
        found.extend(pattern.findall(text))
    return found


# Type alias for clarity.
EntityRegistryLookup = Callable[[str], list[dict]]
"""Returns prior claims that reference the given entity, as dicts with at
least {'claim_id', 'statement', 'attestation_id'}.
"""


def consistency_check(
    claim_statement: str,
    *,
    registry_lookup: Optional[EntityRegistryLookup] = None,
    extractor: Optional[Callable[[str], list[str]]] = None,
) -> dict:
    """Cross-reference the claim against prior claims for shared entities.

    Returns a partial Challenge dict suitable for the harness.

    Behaviour:
    - No registry_lookup → automatic decline with reason
      `no_entity_registry_available`.
    - Registry returns no prior claims for any extracted entity →
      `survived` with gap noting the absence.
    - Registry returns claims that contradict (heuristic: claim text
      contains a negation or a numeric mismatch with a prior claim) →
      `revised` with the contradicting claim_id in revisions.
    - Otherwise → `survived`.
    """
    extract = extractor or _extract_entities
    entities = extract(claim_statement)

    if not entities:
        return {
            "type": "consistency_check",
            "input": "no entities extracted from claim_statement; nothing to cross-reference",
            "outcome": ChallengeOutcome.SURVIVED.value,
            "revisions": None,
        }
    if registry_lookup is None:
        # AUDIT-FIX (R2): entities were extracted but there is no registry to
        # cross-reference them against ⇒ the check could not run ⇒ ERROR
        # (inconclusive), not SURVIVED. We cannot assert consistency we never
        # tested. The harness declines on decline_reason; the outcome stays honest.
        return {
            "type": "consistency_check",
            "input": f"entities extracted: {entities}",
            "outcome": ChallengeOutcome.ERROR.value,
            "revisions": None,
            "decline_reason": "no_entity_registry_available",
        }

    contradictions: list[dict] = []
    examined: list[str] = []
    for entity in entities:
        priors = registry_lookup(entity) or []
        examined.append(f"{entity} ({len(priors)} prior claims)")
        for prior in priors:
            if _contradicts(claim_statement, prior.get("statement", "")):
                contradictions.append(prior)

    if contradictions:
        return {
            "type": "consistency_check",
            "input": (
                f"cross-referenced entities {entities} against the entity registry; "
                f"found {len(contradictions)} contradicting prior claim(s)"
            ),
            "outcome": ChallengeOutcome.REVISED.value,
            "revisions": [{"contradicting_claim_id": c.get("claim_id")} for c in contradictions],
        }
    return {
        "type": "consistency_check",
        "input": f"cross-referenced {len(examined)} entities; no contradictions found ({examined})",
        "outcome": ChallengeOutcome.SURVIVED.value,
        "revisions": None,
    }


def _contradicts(a: str, b: str) -> bool:
    """Heuristic contradiction detector.

    Real implementation should use the enrichment LM; this is a quick
    rule-based fallback that catches obvious negations and amount/date
    mismatches. False negatives are expected; false positives must be
    rare to keep the `revised` rate believable.
    """
    a_lower, b_lower = a.lower(), b.lower()
    a_negated = any(word in a_lower for word in (" not ", " no ", " never ", " denies "))
    b_negated = any(word in b_lower for word in (" not ", " no ", " never ", " denies "))
    if a_negated != b_negated:
        # One is negated, the other isn't, and they share entities → contradiction signal.
        return True
    a_amounts = set(_AMOUNT_USD_RE.findall(a))
    b_amounts = set(_AMOUNT_USD_RE.findall(b))
    if a_amounts and b_amounts and a_amounts.isdisjoint(b_amounts):
        return True
    a_dates = set(_DATE_ISO_RE.findall(a))
    b_dates = set(_DATE_ISO_RE.findall(b))
    if a_dates and b_dates and a_dates.isdisjoint(b_dates):
        return True
    return False
