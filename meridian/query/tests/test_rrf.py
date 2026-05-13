"""RRF behavior tests."""

from __future__ import annotations

from meridian.query.rrf import reciprocal_rank_fusion


def test_single_ranking_preserves_order() -> None:
    out = reciprocal_rank_fusion([["a", "b", "c"]])
    assert [doc for doc, _ in out] == ["a", "b", "c"]
    # Scores monotonically decrease.
    scores = [s for _, s in out]
    assert all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1))


def test_two_rankings_promote_overlap() -> None:
    """A doc ranking high in both should beat a doc ranking high in one."""
    bm25 = ["a", "b", "c", "d"]
    dense = ["d", "a", "x", "y"]
    out = dict(reciprocal_rank_fusion([bm25, dense]))
    assert out["a"] > out["b"]
    assert out["a"] > out["x"]
    assert out["d"] > out["x"]


def test_documents_appearing_in_only_one_ranking_remain_present() -> None:
    out = dict(reciprocal_rank_fusion([["a", "b"], ["c", "d"]]))
    assert set(out.keys()) == {"a", "b", "c", "d"}


def test_empty_rankings_returns_empty() -> None:
    assert reciprocal_rank_fusion([]) == []
    assert reciprocal_rank_fusion([[], []]) == []


def test_k_smoothing_affects_decay() -> None:
    """Higher k flattens the curve so positions matter less."""
    ranking = ["a", "b", "c"]
    high_k = dict(reciprocal_rank_fusion([ranking], k=1000))
    low_k = dict(reciprocal_rank_fusion([ranking], k=10))
    # In high_k, a/b/c scores are closer; in low_k they're more spread.
    high_spread = high_k["a"] - high_k["c"]
    low_spread = low_k["a"] - low_k["c"]
    assert low_spread > high_spread
