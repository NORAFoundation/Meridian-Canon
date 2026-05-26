-- Phase 7: ParadeDB BM25 full-text search (replaces Postgres tsvector for BM25 scoring)
-- Requires: ParadeDB Postgres extension (pg_search)
-- Install: use paradedb/paradedb Docker image, or CALL paradedb.install() on compatible Postgres
--
-- If pg_search is not available, fall back to B0_chunks_fts.sql (tsvector).
-- Feature flag: set MERIDIAN_USE_PARADEDB=1 environment variable to activate.
--
-- This migration is ADDITIVE — B0 tsvector indexes remain as fallback.

-- Guard: only run if pg_search extension is available
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_search') THEN
        CREATE EXTENSION IF NOT EXISTS pg_search;

        -- Create ParadeDB BM25 index on chunks table
        -- Drops existing ParadeDB index if present (idempotent)
        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE indexname = 'chunks_bm25_idx'
        ) THEN
            CALL paradedb.drop_bm25('chunks_bm25');
        END IF;

        CALL paradedb.create_bm25(
            index_name  => 'chunks_bm25',
            table_name  => 'chunks',
            key_field   => 'id',
            text_fields => paradedb.field(
                'text',
                tokenizer => paradedb.tokenizer('en_stem')
            )
        );

        RAISE NOTICE 'ParadeDB BM25 index created on chunks.text';
    ELSE
        RAISE NOTICE 'pg_search not available — skipping ParadeDB BM25 index (using tsvector fallback)';
    END IF;
END;
$$;
