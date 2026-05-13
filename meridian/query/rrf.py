"""Reciprocal Rank Fusion (Cormack, Clarke, Buttcher 2009; paper §6.7.2).

Score formula: RRF(d) = sum over rankings i of 1 / (k + rank_i(d))

k=60 is the empirical sweet spot reported in the original paper and
re-confirmed across many TREC tracks. The value is exposed as a parameter
for diagnostic experiments but should not be tuned per-corpus without
measurement.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence


def reciprocal_rank_fusion(
    rankings: Sequence[Sequence],
    *,
    k: int = 60,
) -> list[tuple[object, float]]:
    """Fuse multiple ranked lists into a single ranking.

    Args:
        rankings: each ranking is an ordered sequence of doc identifiers
            (most relevant first). Identifiers are opaque; equality drives
            cross-ranking aggregation.
        k: smoothing constant per Cormack et al.; defaults to 60.

    Returns:
        List of (doc_id, fused_score) sorted by fused_score descending.
        A doc_id appearing in only one ranking still appears in the output;
        absence from a ranking contributes 0 (not a penalty).
    """
    scores: dict[object, float] = defaultdict(float)
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] += 1.0 / (k + rank)
    return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
