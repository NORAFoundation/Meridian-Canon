"""Hybrid retrieval: lexical (Postgres tsvector) + dense (pgvector cosine)
fused via RRF, with optional cross-encoder re-rank (paper §6.7).

Returns ranked SearchResult objects. The caller can pass these to
attestation.build_search_attestation() to seal the retrieval as a
Canon-conformant SearchAttestation.
"""

from __future__ import annotations

import os as _os
from dataclasses import dataclass, field
from typing import Optional

from .embeddings import embed_query, vector_to_pgvector_literal
from .rrf import reciprocal_rank_fusion
from . import reranker


@dataclass
class SearchResult:
    chunk_id: str
    document_id: str
    text: str
    matter_id: Optional[str]
    fused_score: float
    rerank_score: Optional[float] = None
    bm25_rank: Optional[int] = None
    dense_rank: Optional[int] = None


@dataclass
class HybridSearch:
    """Query the corpus with hybrid lexical + dense retrieval.

    Args:
        conn: psycopg connection (caller manages transaction).
        bm25_k: number of lexical candidates to fetch.
        dense_k: number of dense candidates to fetch.
        rrf_k_smoothing: k parameter for reciprocal-rank-fusion (default 60).
        rerank: whether to run cross-encoder re-ranking on the fused candidates.
        rerank_pool_multiplier: how many fused candidates to feed the reranker
            (paper §6.7.3 uses 4×).
    """

    conn: object
    bm25_k: int = 50
    dense_k: int = 50
    rrf_k_smoothing: int = 60
    rerank: bool = False
    rerank_pool_multiplier: int = 4

    def search(self, query: str, *, top_k: int = 20, matter_id: Optional[str] = None) -> list[SearchResult]:
        bm25 = self._bm25_search(query, k=self.bm25_k, matter_id=matter_id)
        dense = self._dense_search(query, k=self.dense_k, matter_id=matter_id)

        bm25_ids = [row["chunk_id"] for row in bm25]
        dense_ids = [row["chunk_id"] for row in dense]

        fused = reciprocal_rank_fusion([bm25_ids, dense_ids], k=self.rrf_k_smoothing)

        # Hydrate top candidates.
        candidate_ids = [doc_id for doc_id, _ in fused[: top_k * self.rerank_pool_multiplier]]
        if not candidate_ids:
            return []

        rows = self._hydrate(candidate_ids, matter_id=matter_id)
        rows_by_id = {r["chunk_id"]: r for r in rows}

        bm25_rank_by_id = {cid: i + 1 for i, cid in enumerate(bm25_ids)}
        dense_rank_by_id = {cid: i + 1 for i, cid in enumerate(dense_ids)}

        # Optional cross-encoder re-rank.
        rerank_scores: dict[str, float] = {}
        if self.rerank and candidate_ids:
            pairs = [(cid, rows_by_id[cid]["text"]) for cid in candidate_ids if cid in rows_by_id]
            for cid, score in reranker.rerank(query, pairs, top_k=top_k * self.rerank_pool_multiplier):
                rerank_scores[cid] = score

        results: list[SearchResult] = []
        order = (
            sorted(rerank_scores.items(), key=lambda kv: kv[1], reverse=True)
            if rerank_scores
            else fused
        )
        for cid, score in order:
            cid = str(cid)
            row = rows_by_id.get(cid)
            if row is None:
                continue
            results.append(SearchResult(
                chunk_id=cid,
                document_id=str(row["document_id"]),
                text=row["text"],
                matter_id=str(row["matter_id"]) if row.get("matter_id") else None,
                fused_score=float(dict(fused).get(cid, 0.0)),
                rerank_score=rerank_scores.get(cid),
                bm25_rank=bm25_rank_by_id.get(cid),
                dense_rank=dense_rank_by_id.get(cid),
            ))
            if len(results) >= top_k:
                break
        return results

    # --- Internal queries -------------------------------------------------

    def _bm25_search(self, query: str, *, k: int, matter_id: Optional[str]) -> list[dict]:
        """BM25 text search. Uses ParadeDB pg_search if MERIDIAN_USE_PARADEDB=1, else tsvector."""
        use_paradedb = _os.environ.get("MERIDIAN_USE_PARADEDB", "").strip() == "1"
        if use_paradedb:
            return self._paradedb_search(query, k=k, matter_id=matter_id)
        return self._tsvector_search(query, k=k, matter_id=matter_id)

    def _tsvector_search(self, query: str, *, k: int, matter_id: Optional[str]) -> list[dict]:
        """Original tsvector BM25 approximation (fallback when ParadeDB not enabled)."""
        sql = (
            "SELECT c.id::text AS chunk_id, "
            "       ts_rank(c.tsv, plainto_tsquery('english', %s)) AS bm25_score "
            "FROM chunks c "
        )
        params: list = [query]
        if matter_id:
            sql += "JOIN documents d ON c.document_id = d.id "
            sql += "WHERE c.tsv @@ plainto_tsquery('english', %s) AND d.matter_id = %s "
            params.extend([query, matter_id])
        else:
            sql += "WHERE c.tsv @@ plainto_tsquery('english', %s) "
            params.append(query)
        sql += "ORDER BY bm25_score DESC LIMIT %s"
        params.append(k)
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    def _paradedb_search(self, query: str, *, k: int, matter_id: Optional[str]) -> list[dict]:
        """ParadeDB BM25 search via @@@ operator (requires pg_search extension)."""
        # Escape single quotes in query to prevent SQL injection
        safe_query = query.replace("'", "''")
        sql = (
            "SELECT c.id::text AS chunk_id, "
            "       paradedb.score(c.id) AS bm25_score "
            "FROM chunks c "
            "WHERE c @@@ paradedb.parse('text:' || %s) "
        )
        params: list = [safe_query]
        if matter_id:
            sql += "AND c.document_id IN (SELECT id FROM documents WHERE matter_id = %s) "
            params.append(matter_id)
        sql += "ORDER BY bm25_score DESC LIMIT %s"
        params.append(k)
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return [{"chunk_id": row[0], "bm25_score": row[1]} for row in cur.fetchall()]

    def _dense_search(self, query: str, *, k: int, matter_id: Optional[str]) -> list[dict]:
        vec_str = vector_to_pgvector_literal(embed_query(query))
        sql = (
            "SELECT e.chunk_id::text AS chunk_id, "
            "       1 - (e.vector <=> %s::vector) AS cosine_score "
            "FROM embeddings e "
        )
        params: list = [vec_str]
        if matter_id:
            sql += "JOIN chunks c ON e.chunk_id = c.id "
            sql += "JOIN documents d ON c.document_id = d.id "
            sql += "WHERE d.matter_id = %s "
            params.append(matter_id)
        sql += "ORDER BY e.vector <=> %s::vector LIMIT %s"
        params.extend([vec_str, k])
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    def _hydrate(self, chunk_ids: list[str], *, matter_id: Optional[str]) -> list[dict]:
        sql = (
            "SELECT c.id::text AS chunk_id, c.document_id::text AS document_id, "
            "       c.text, d.matter_id::text AS matter_id "
            "FROM chunks c "
            "JOIN documents d ON c.document_id = d.id "
            "WHERE c.id = ANY(%s::uuid[]) "
        )
        params: list = [chunk_ids]
        if matter_id:
            sql += "AND d.matter_id = %s"
            params.append(matter_id)
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())
