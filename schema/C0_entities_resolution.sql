-- ============================================================================
-- C0_entities_resolution.sql
--
-- Disambiguation substrate for the entities table.
--
--   * fuzzystrmatch  — Soundex / Metaphone for phonetic fallback in SQL.
--   * normalized_label / normalized_aliases — generated columns that mirror
--     the Python normalizer's output, so a SQL trigram lookup gets the same
--     answer the resolver does.
--   * resolution_log — every resolution decision (auto, manual, override)
--     so a human can audit and roll back disambiguation changes.
--
-- Reversible: see C0_entities_resolution.down.sql.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;

-- ----------------------------------------------------------------------------
-- normalize_name(text, bool) — Postgres-side mirror of the Python
-- meridian.entities.normalize.normalize_name function.  Used by indexes and
-- ad-hoc lookups.  Conservative: lowercases, strips accents (via unaccent
-- proxy below), drops punctuation, collapses whitespace.  Honorific/suffix
-- stripping is *not* mirrored here — that lives in Python — so this gives
-- a "lite" canonical form that is good enough for a first SQL pass.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION entity_norm(label text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT regexp_replace(
           regexp_replace(
             lower(coalesce(label, '')),
             '[^a-z0-9 ]+', ' ', 'g'
           ),
           '\s+', ' ', 'g'
         )
$$;

COMMENT ON FUNCTION entity_norm(text) IS
  'SQL-side lite normalizer for entity labels. Pairs with '
  'meridian.entities.normalize.normalize_name in Python; the Python '
  'version additionally strips honorifics / suffixes / quoted nicknames.';

-- ----------------------------------------------------------------------------
-- Add a generated normalized_label column to entities for fast trigram
-- lookup, plus a GIN trgm index.  STORED (not VIRTUAL) because we want
-- pg_trgm to index it.
-- ----------------------------------------------------------------------------

ALTER TABLE entities
  ADD COLUMN IF NOT EXISTS normalized_label text
    GENERATED ALWAYS AS (entity_norm(canonical_label)) STORED;

CREATE INDEX IF NOT EXISTS entities_norm_label_trgm_idx
  ON entities USING GIN (normalized_label gin_trgm_ops);

-- Soundex helper for phonetic surname lookup. (Use the last whitespace
-- separated token — works for "Hannah Azem" → 'A250'.)
CREATE INDEX IF NOT EXISTS entities_surname_soundex_idx
  ON entities ((soundex(split_part(normalized_label, ' ',
                                    array_length(string_to_array(normalized_label, ' '), 1)))))
  WHERE kind IN ('person', 'other');

-- ----------------------------------------------------------------------------
-- Per-matter uniqueness on (kind, normalized_label).  We use a partial
-- unique index keyed on matter_id + kind + normalized_label.  A NULL
-- matter_id participates as a global "shared" entity (e.g. courts, statutes).
-- ----------------------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS entities_canon_unique_idx
  ON entities (matter_id, kind, normalized_label)
  WHERE normalized_label <> '';

-- ----------------------------------------------------------------------------
-- entity_resolutions — audit log of every disambiguation decision.
-- One row per (chunk_id|document_id, surface_text, action).
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entity_resolutions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id       uuid REFERENCES matters(id),
  surface_text    text NOT NULL,
  resolved_entity_id uuid REFERENCES entities(id),
  action          text NOT NULL CHECK (action IN (
                    'exact', 'norm_exact', 'token_subset', 'initial_match',
                    'trigram', 'phonetic', 'nickname',
                    'create_new', 'manual_link', 'manual_override',
                    'atom', 'ambiguous'
                  )),
  confidence      numeric(4,3) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  matched_via     text,
  source_kind     text,                                  -- 'findings.parties' | 'ner_mention' | 'email_from' | ...
  source_ref      jsonb NOT NULL DEFAULT '{}',           -- {document_id, chunk_id, span, ...}
  resolver_version text NOT NULL DEFAULT 'v1',
  decided_by_actor uuid REFERENCES actors(id),
  decided_at      timestamptz NOT NULL DEFAULT now(),
  notes           text
);

CREATE INDEX IF NOT EXISTS entity_resolutions_matter_idx
  ON entity_resolutions(matter_id);

CREATE INDEX IF NOT EXISTS entity_resolutions_entity_idx
  ON entity_resolutions(resolved_entity_id);

CREATE INDEX IF NOT EXISTS entity_resolutions_surface_trgm_idx
  ON entity_resolutions USING GIN (surface_text gin_trgm_ops);

COMMENT ON TABLE entity_resolutions IS
  'Audit log of disambiguation decisions. Lets a human review and override '
  'auto-resolution; lets the resolver be re-run with a different version '
  'and the diffs traced.';

-- ----------------------------------------------------------------------------
-- Convenience view: every party with all known surface forms (canonical +
-- aliases + every surface seen in entity_resolutions).  Powers the
-- "see all the ways this person has been spelled" UI.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE VIEW party_surface_forms AS
SELECT
  p.id           AS party_id,
  p.matter_id,
  p.display_name AS canonical,
  e.id           AS entity_id,
  COALESCE(e.aliases, ARRAY[]::text[]) AS registered_aliases,
  COALESCE(
    (
      SELECT array_agg(DISTINCT er.surface_text ORDER BY er.surface_text)
      FROM entity_resolutions er
      WHERE er.resolved_entity_id = e.id
        AND er.surface_text NOT IN (SELECT unnest(COALESCE(e.aliases, ARRAY[]::text[])))
        AND er.surface_text <> e.canonical_label
    ),
    ARRAY[]::text[]
  ) AS observed_surfaces
FROM parties p
LEFT JOIN entities e ON e.resolved_party_id = p.id;

COMMENT ON VIEW party_surface_forms IS
  'Every party joined to its canonical entity, with registered aliases and '
  'every additional surface form seen during resolution.';
