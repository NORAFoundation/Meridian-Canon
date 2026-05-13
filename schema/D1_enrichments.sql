-- D1_enrichments.sql — preprocessing enrichment columns
-- Run: psql $DATABASE_URL -f schema/D1_enrichments.sql

-- 1. Statute normalization columns on legal_citations
ALTER TABLE legal_citations
  ADD COLUMN IF NOT EXISTS statute_section  text,
  ADD COLUMN IF NOT EXISTS statute_label    text,
  ADD COLUMN IF NOT EXISTS jurisdiction     text;

CREATE INDEX IF NOT EXISTS lc_statute_section_idx
  ON legal_citations(statute_section)
  WHERE statute_section IS NOT NULL;

CREATE INDEX IF NOT EXISTS lc_jurisdiction_idx
  ON legal_citations(jurisdiction)
  WHERE jurisdiction IS NOT NULL;

-- 2. Resolved date on entity_resolutions (for DATE entities)
ALTER TABLE entity_resolutions
  ADD COLUMN IF NOT EXISTS resolved_date date;

CREATE INDEX IF NOT EXISTS er_resolved_date_idx
  ON entity_resolutions(resolved_date)
  WHERE resolved_date IS NOT NULL;

-- 3. Document type classification on documents
ALTER TABLE documents
  ADD COLUMN IF NOT EXISTS doc_type text;

CREATE INDEX IF NOT EXISTS documents_doc_type_idx
  ON documents(doc_type)
  WHERE doc_type IS NOT NULL;
