-- Phase 7: pgvectorscale StreamingDiskANN index (replaces ivfflat for better recall + speed)
-- Requires: pgvectorscale extension (timescale/pgvectorscale)
-- Install: docker image timescale/timescaledb-ha or extension from pgvectorscale repo
--
-- This migration replaces the ivfflat index on embeddings.vector with StreamingDiskANN.
-- Query interface is unchanged (still uses <=> cosine operator).
-- Feature flag: runs automatically if pgvectorscale is installed.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vectorscale') THEN
        CREATE EXTENSION IF NOT EXISTS vectorscale CASCADE;

        -- Drop old ivfflat index if present
        DROP INDEX IF EXISTS embeddings_vector_idx;
        DROP INDEX IF EXISTS embeddings_ivfflat_idx;

        -- Create StreamingDiskANN index (better recall, faster at scale)
        CREATE INDEX IF NOT EXISTS embeddings_diskann_idx
            ON embeddings USING diskann (vector vector_cosine_ops)
            WITH (num_neighbors = 32, search_list_size = 100);

        RAISE NOTICE 'pgvectorscale StreamingDiskANN index created on embeddings.vector';
    ELSE
        RAISE NOTICE 'vectorscale not available — keeping existing pgvector index';
    END IF;
END;
$$;
