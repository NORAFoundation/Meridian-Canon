-- ============================================================================
-- 00_setup.sql
-- Extensions, common helpers, session-variable wiring.
-- Run as a superuser the first time (extensions need it).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS vector;       -- pgvector for embeddings
CREATE EXTENSION IF NOT EXISTS postgis;      -- geography for location_pings
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- trigram fuzzy text search
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- mixed-type GIN composite indexes

-- ----------------------------------------------------------------------------
-- Session-variable plumbing for RLS.
--
-- The application sets `app.current_actor_id` per connection (or per
-- transaction with SET LOCAL).  Every RLS policy reads this.  If unset,
-- current_actor_id() returns NULL and most policies will deny.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION current_actor_id() RETURNS uuid AS $$
  SELECT NULLIF(current_setting('app.current_actor_id', true), '')::uuid
$$ LANGUAGE sql STABLE;

-- The role string is read from the actors table; cached per-statement via STABLE.
-- Populated after actors is created (see 10_core.sql).

-- ----------------------------------------------------------------------------
-- Hash-chain helper for audit_log.  digest() returns bytea; we store hex.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION sha256_hex(s text) RETURNS text AS $$
  SELECT encode(digest(s, 'sha256'), 'hex')
$$ LANGUAGE sql IMMUTABLE;

-- ----------------------------------------------------------------------------
-- A canonical "minor units" check: financial amounts always integer cents.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION assert_minor_units(amount bigint) RETURNS bigint AS $$
  SELECT amount  -- placeholder; CHECK constraints do the real validation per-table
$$ LANGUAGE sql IMMUTABLE;
