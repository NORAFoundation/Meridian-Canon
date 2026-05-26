-- cookbook.sql — example queries for Meridian-Canon local development
-- Run interactively: psql $DB_URL -f cookbook.sql
-- These are reference queries — they will return empty results on a fresh dev stack.

-- List all matters
SELECT matter_id, matter_ref, description, status FROM matters ORDER BY created_at DESC;

-- Count records by table
SELECT 'documents'     AS tbl, COUNT(*) FROM documents
UNION ALL
SELECT 'communications', COUNT(*) FROM communications
UNION ALL
SELECT 'court_events',   COUNT(*) FROM court_events
UNION ALL
SELECT 'attestations',   COUNT(*) FROM attestations
ORDER BY tbl;

-- Recent attestations
SELECT attestation_id, kind, subject, issued_at
FROM attestations
ORDER BY issued_at DESC
LIMIT 20;

-- Hybrid search example (requires pgvector extension and populated embeddings)
-- SELECT chunk_id, document_id, content, 1 - (embedding <=> '[...]'::vector) AS cosine_sim
-- FROM chunks
-- ORDER BY embedding <=> '[...]'::vector
-- LIMIT 10;
