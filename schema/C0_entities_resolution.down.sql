-- Reverse C0_entities_resolution.sql.
-- Drops in dependency order. Does NOT drop the fuzzystrmatch extension —
-- it's harmless to leave installed and other modules may depend on it.

DROP VIEW IF EXISTS party_surface_forms;

DROP TABLE IF EXISTS entity_resolutions;

DROP INDEX IF EXISTS entities_canon_unique_idx;
DROP INDEX IF EXISTS entities_surname_soundex_idx;
DROP INDEX IF EXISTS entities_norm_label_trgm_idx;

ALTER TABLE entities DROP COLUMN IF EXISTS normalized_label;

DROP FUNCTION IF EXISTS entity_norm(text);

-- Intentionally left in place:
--   CREATE EXTENSION fuzzystrmatch;
