"""Tests for ParadeDB feature flag routing in HybridSearch."""
import os
from unittest.mock import MagicMock, patch
from meridian.query.search import HybridSearch


def _make_search(conn=None):
    conn = conn or MagicMock()
    return HybridSearch(conn=conn)


def test_uses_tsvector_by_default(monkeypatch):
    """Without MERIDIAN_USE_PARADEDB, uses tsvector path."""
    monkeypatch.delenv("MERIDIAN_USE_PARADEDB", raising=False)
    hs = _make_search()
    with patch.object(hs, "_tsvector_search", return_value=[]) as mock_ts, \
         patch.object(hs, "_paradedb_search", return_value=[]) as mock_pd:
        hs._bm25_search("test query", k=10, matter_id=None)
        mock_ts.assert_called_once()
        mock_pd.assert_not_called()


def test_uses_paradedb_when_flag_set(monkeypatch):
    """With MERIDIAN_USE_PARADEDB=1, uses ParadeDB path."""
    monkeypatch.setenv("MERIDIAN_USE_PARADEDB", "1")
    hs = _make_search()
    with patch.object(hs, "_tsvector_search", return_value=[]) as mock_ts, \
         patch.object(hs, "_paradedb_search", return_value=[]) as mock_pd:
        hs._bm25_search("test query", k=10, matter_id=None)
        mock_pd.assert_called_once()
        mock_ts.assert_not_called()


def test_paradedb_flag_value_zero_uses_tsvector(monkeypatch):
    """MERIDIAN_USE_PARADEDB=0 still uses tsvector."""
    monkeypatch.setenv("MERIDIAN_USE_PARADEDB", "0")
    hs = _make_search()
    with patch.object(hs, "_tsvector_search", return_value=[]) as mock_ts, \
         patch.object(hs, "_paradedb_search", return_value=[]) as mock_pd:
        hs._bm25_search("test query", k=10, matter_id=None)
        mock_ts.assert_called_once()
        mock_pd.assert_not_called()


def test_tsvector_search_builds_correct_sql():
    """_tsvector_search returns [] when DB mock returns no rows."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    hs = HybridSearch(conn=mock_conn)
    result = hs._tsvector_search("test", k=5, matter_id=None)
    assert result == []
    mock_cursor.execute.assert_called_once()
