"""Tests for the audited SQL-construction fixes in HybridSearch.

Covers:
  - CRIT-2: ParadeDB BM25 search must treat the user query as a bound
    literal term (via paradedb.term), never string-build it into the
    query language, and must not manually escape quotes.
  - MED-4: dense vector search must parse the query vector exactly once
    (CTE), not pass the ~8KB literal twice.
"""

from unittest.mock import MagicMock, patch

from meridian.query.search import HybridSearch


def _mock_conn():
    """A connection whose cursor records execute() calls and returns no rows."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn, mock_cursor


# --- CRIT-2: SQL injection in _paradedb_search ---------------------------


def test_paradedb_uses_term_builder_not_parse():
    """The query must go through paradedb.term(field, value), never be
    concatenated into paradedb.parse('text:' || ...)."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    hs._paradedb_search("hello world", k=10, matter_id=None)
    sql = cur.execute.call_args[0][0]
    assert "paradedb.term('text', %s)" in sql
    assert "paradedb.parse" not in sql
    assert "||" not in sql  # no string concatenation of the user value


def test_paradedb_injection_input_is_bound_literal_not_parsed():
    """An injection-style query is passed verbatim as a bound parameter and
    is never escaped or interpolated into the SQL text — paradedb.term
    treats it as a single opaque literal term, not query syntax."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    evil = "foo' AND x:*"
    hs._paradedb_search(evil, k=10, matter_id=None)
    sql, params = cur.execute.call_args[0][0], cur.execute.call_args[0][1]
    # The raw value is a bound parameter, unmodified (no quote-doubling).
    assert evil in params
    assert "foo'' AND" not in params  # the old false-safety escape is gone
    # The dangerous payload never appears in the SQL string itself.
    assert evil not in sql
    assert "x:*" not in sql


def test_paradedb_no_manual_quote_escaping():
    """A query containing single quotes is passed through untouched as a
    parameter (parameterization, not string escaping)."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    q = "O'Brien deposition"
    hs._paradedb_search(q, k=5, matter_id=None)
    params = cur.execute.call_args[0][1]
    assert q in params
    assert "O''Brien" not in params


def test_paradedb_matter_filter_appends_param():
    """matter_id scoping adds a bound parameter without touching the query
    term's parameterization."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    hs._paradedb_search("term", k=7, matter_id="matter-123")
    sql, params = cur.execute.call_args[0][0], cur.execute.call_args[0][1]
    assert "matter_id = %s" in sql
    assert params == ["term", "matter-123", 7]


# --- MED-4: vector double-parse ------------------------------------------


def test_dense_search_binds_vector_once():
    """The query vector literal must be bound exactly once (CTE), not twice."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    with patch("meridian.query.search.embed_query", return_value=[0.1, 0.2, 0.3]), \
         patch("meridian.query.search.vector_to_pgvector_literal",
               return_value="[0.1,0.2,0.3]") as mock_lit:
        hs._dense_search("a query", k=10, matter_id=None)
    sql, params = cur.execute.call_args[0][0], cur.execute.call_args[0][1]
    # CTE parses the vector once.
    assert "WITH q AS (SELECT %s::vector AS qvec)" in sql
    # The ::vector cast appears exactly once now (only inside the CTE).
    assert sql.count("::vector") == 1
    # The 8KB literal is bound exactly once.
    assert params.count("[0.1,0.2,0.3]") == 1
    # Both SELECT and ORDER BY reference the single parsed vector.
    assert "1 - (e.vector <=> q.qvec)" in sql
    assert "ORDER BY e.vector <=> q.qvec" in sql
    mock_lit.assert_called_once()


def test_dense_search_with_matter_filter_binds_vector_once():
    """The CTE rewrite holds with matter scoping; explicit JOINs bind to e,
    and q is cross-joined so q.qvec stays in scope."""
    conn, cur = _mock_conn()
    hs = HybridSearch(conn=conn)
    with patch("meridian.query.search.embed_query", return_value=[0.1]), \
         patch("meridian.query.search.vector_to_pgvector_literal",
               return_value="[0.1]"):
        hs._dense_search("q", k=5, matter_id="m-1")
    sql, params = cur.execute.call_args[0][0], cur.execute.call_args[0][1]
    assert sql.count("::vector") == 1
    assert params.count("[0.1]") == 1
    # JOINs to chunks/documents precede the CROSS JOIN q, so e is in scope.
    assert sql.index("JOIN chunks c") < sql.index("CROSS JOIN q")
    assert sql.index("JOIN documents d") < sql.index("CROSS JOIN q")
    assert "d.matter_id = %s" in sql
    assert params == ["[0.1]", "m-1", 5]
