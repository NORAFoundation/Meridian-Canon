-- ============================================================================
-- B0_chunks_fts.sql  (Phase E: hybrid retrieval)
--
-- Adds Postgres FTS5-equivalent (tsvector + GIN) to chunks for the lexical
-- side of hybrid retrieval. The dense side already uses pgvector via
-- embeddings.vector. RRF (Reciprocal Rank Fusion) fuses the two rankings
-- in application code; cross-encoder re-ranking is a third optional pass.
--
-- Down: schema/B0_chunks_fts.down.sql
-- ============================================================================

-- Generated tsvector column. STORED so we don't recompute per query.
-- Uses the 'english' configuration with default token weights.
ALTER TABLE chunks
  ADD COLUMN IF NOT EXISTS tsv tsvector
    GENERATED ALWAYS AS (to_tsvector('english', coalesce(text, ''))) STORED;

CREATE INDEX IF NOT EXISTS chunks_tsv_idx ON chunks USING GIN(tsv);

-- Column weights are baked into ts_rank weighting in application code:
-- title (A), body (B), participant (C). For now the chunk has only `text`,
-- so all weights are equal; richer weighting awaits per-document field
-- decomposition at chunk time.

-- Helpful query helper view for diagnostic SQL.
CREATE OR REPLACE VIEW chunks_search AS
SELECT
  c.id              AS chunk_id,
  c.document_id,
  c.text,
  c.tsv,
  d.matter_id,
  d.declared_filename
FROM chunks c
JOIN documents d ON c.document_id = d.id;

COMMENT ON COLUMN chunks.tsv IS
  'Generated tsvector over chunks.text; English config; STORED. '
  'Used by meridian.query.search for the lexical side of hybrid retrieval.';
