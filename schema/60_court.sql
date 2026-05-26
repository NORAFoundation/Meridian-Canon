-- ============================================================================
-- 60_court.sql
-- Court cases, docket entries, immutable WARC-backed snapshots.
-- ============================================================================

CREATE TABLE court_cases (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  jurisdiction             text NOT NULL,                            -- 'WI-Example', 'US-WDWi', 'US-7thCir'
  court_name               text NOT NULL,                            -- 'Example County Circuit Court'
  case_number              text NOT NULL,                            -- '2024CV000123'
  case_type                text,                                     -- 'CV', 'CF', 'FA', 'JC', etc.
  caption                  text,
  filed_at                 date,
  status                   text,                                     -- 'open' | 'closed' | 'sealed' | etc.
  presiding_judge          text,
  parties_summary          jsonb NOT NULL DEFAULT '[]',              -- [{role, name, attorney}, ...]
  is_sealed                boolean NOT NULL DEFAULT false,
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  created_at               timestamptz NOT NULL DEFAULT now(),
  UNIQUE (jurisdiction, case_number)
);

CREATE INDEX court_cases_matter_idx ON court_cases(matter_id);
CREATE INDEX court_cases_caption_trgm_idx ON court_cases USING GIN (caption gin_trgm_ops);

CREATE TABLE docket_entries (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  court_case_id            uuid NOT NULL REFERENCES court_cases(id) ON DELETE CASCADE,
  sequence_no              int,                                       -- ordering on docket
  entry_date               date,
  entry_type               text,                                      -- 'Motion', 'Order', 'Filing', etc.
  description              text,
  filing_party             text,
  attached_document_ids    uuid[] NOT NULL DEFAULT '{}',              -- references documents
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  parser_version           text,
  notes                    text,
  UNIQUE (court_case_id, sequence_no)
);

CREATE INDEX docket_entries_case_idx ON docket_entries(court_case_id, sequence_no);
CREATE INDEX docket_entries_date_idx ON docket_entries(entry_date);
CREATE INDEX docket_entries_desc_trgm_idx ON docket_entries USING GIN (description gin_trgm_ops);

-- ----------------------------------------------------------------------------
-- docket_snapshots: every visit to a docket page produces an immutable
-- WARC-backed snapshot.  This is the authoritative point-in-time record;
-- if the court later seals or amends an entry, prior snapshots remain.
-- ----------------------------------------------------------------------------

CREATE TABLE docket_snapshots (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  court_case_id            uuid NOT NULL REFERENCES court_cases(id) ON DELETE CASCADE,
  fetched_at               timestamptz NOT NULL,
  warc_storage_uri         text NOT NULL,
  warc_sha256              text NOT NULL,
  parsed_body_sha256       text NOT NULL,                            -- hash of normalized parse
  acquisition_id           uuid REFERENCES acquisitions(id),
  parser_version           text NOT NULL,
  http_status              int,
  http_response_meta       jsonb NOT NULL DEFAULT '{}',
  diff_from_previous       jsonb,                                     -- structural diff vs. prior snapshot
  notes                    text,
  CHECK (length(warc_sha256) = 64),
  CHECK (length(parsed_body_sha256) = 64)
);

CREATE INDEX docket_snapshots_case_idx ON docket_snapshots(court_case_id, fetched_at);
