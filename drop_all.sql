-- drop_all.sql — drops all Meridian-Canon schema objects for a clean slate.
-- WARNING: This is destructive. For development use only.
-- Usage: psql $DB_URL -f drop_all.sql

BEGIN;

-- Drop all tables in reverse dependency order
DROP TABLE IF EXISTS attestations CASCADE;
DROP TABLE IF EXISTS chunks CASCADE;
DROP TABLE IF EXISTS embeddings CASCADE;
DROP TABLE IF EXISTS entities CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS communications CASCADE;
DROP TABLE IF EXISTS court_events CASCADE;
DROP TABLE IF EXISTS sources CASCADE;
DROP TABLE IF EXISTS acquisitions CASCADE;
DROP TABLE IF EXISTS productions CASCADE;
DROP TABLE IF EXISTS records_requests CASCADE;
DROP TABLE IF EXISTS parties CASCADE;
DROP TABLE IF EXISTS actors CASCADE;
DROP TABLE IF EXISTS matters CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;

-- Drop extensions (optional — comment out if shared with other DBs)
-- DROP EXTENSION IF EXISTS vector CASCADE;
-- DROP EXTENSION IF EXISTS postgis CASCADE;
-- DROP EXTENSION IF EXISTS pg_trgm CASCADE;
-- DROP EXTENSION IF EXISTS btree_gin CASCADE;

COMMIT;
