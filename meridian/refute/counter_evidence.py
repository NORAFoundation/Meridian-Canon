"""Counter-evidence challenge: semantic search via the claim's negation
(paper §6.6.1).

For each claim, query the corpus with a negation of the claim. If a
high-confidence opposing document is retrieved, the claim is `revised`
and the opposing support is added to its gaps.

This module is index-agnostic: callers pass a `search_callable` that
takes a query string and returns ranked results. When the index is not
available, the harness records this as a decline with reason.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from meridian.canon.schema import ChallengeOutcome


# Phrasings that signal a claim is asserting positive content; we negate
# by prepending "not" to the verb. This is heuristic; production callers
# should pass a more sophisticated negator.
_FROM_RE = re.compile(r"\bfrom\b", re.IGNORECASE)
_IS_RE = re.compile(r"\bis\b", re.IGNORECASE)


def negate(claim_statement: str) -> str:
    """Heuristic negator. Replace 'from' with 'not from'; 'is' with 'is not'.

    Real callers should use the enrichment LM to produce a high-quality
    negation. This is a fallback that produces *some* counter-query when
    no LM is available.
    """
    s = claim_statement
    # Try simple substitutions first.
    if " not " in s.lower():
        # Already negated; return as-is to avoid double negation.
        return s
    s = _FROM_RE.sub("not from", s, count=1)
    s = _IS_RE.sub("is not", s, count=1)
    if s == claim_statement:
        # No substitution made; fall back to prefix.
        return f"opposing evidence to: {claim_statement}"
    return s


SearchCallable = Callable[[str, int], list[dict]]
"""Returns a list of ranked results. Each result must have at least
{'doc_id', 'score', 'excerpt'}; higher score = more relevant.
"""


def counter_evidence(
    claim_statement: str,
    *,
    search: Optional[SearchCallable] = None,
    threshold: float = 0.7,
    top_k: int = 5,
) -> dict:
    """Query the corpus with the claim's negation; check for high-confidence opposers.

    Returns a partial Challenge dict.

    Behaviour:
    - No search callable → outcome `survived`, decline_reason populated.
    - Search returns nothing or only low-confidence hits → `survived`.
    - Top hit's score ≥ threshold → `revised`, opposing doc_id recorded.
    """
    query = negate(claim_statement)
    if search is None:
        return {
            "type": "counter_evidence",
            "input": f"would have queried: {query!r}",
            "outcome": ChallengeOutcome.SURVIVED.value,
            "revisions": None,
            "decline_reason": "no_search_index_available_to_query",
        }
    try:
        hits = search(query, top_k) or []
    except Exception as e:
        return {
            "type": "counter_evidence",
            "input": f"queried {query!r}; search error: {e}",
            "outcome": ChallengeOutcome.SURVIVED.value,
            "revisions": None,
            "decline_reason": f"search_callable_raised_{type(e).__name__}",
        }
    if not hits:
        return {
            "type": "counter_evidence",
            "input": f"queried {query!r}; no results",
            "outcome": ChallengeOutcome.SURVIVED.value,
            "revisions": None,
        }
    top = hits[0]
    if top.get("score", 0.0) >= threshold:
        return {
            "type": "counter_evidence",
            "input": f"queried {query!r}; opposing document at score {top.get('score'):.3f}: {top.get('doc_id')}",
            "outcome": ChallengeOutcome.REVISED.value,
            "revisions": [{
                "opposing_doc_id": top.get("doc_id"),
                "score": float(top.get("score", 0.0)),
                "excerpt": (top.get("excerpt") or "")[:200],
            }],
        }
    return {
        "type": "counter_evidence",
        "input": (
            f"queried {query!r}; top hit score {top.get('score', 0.0):.3f} "
            f"below threshold {threshold}"
        ),
        "outcome": ChallengeOutcome.SURVIVED.value,
        "revisions": None,
    }
