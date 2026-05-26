-- ============================================================================
-- D0_citations.sql  (Phase D: legal citation graph)
--
-- Stores citations extracted from chunks (via eyecite) and links them
-- to CourtListener opinions for cross-reference and citation graph analysis.
--
-- Architecture:
--   chunks ──→ legal_citations ──→ courtlistener_opinions (cache)
--
-- Down: schema/D0_citations.down.sql
-- ============================================================================

-- ----------------------------------------------------------------------------
-- courtlistener_opinions: lightweight cache of CL opinion metadata.
-- We don't replicate full opinions — just enough to close the citation
-- graph and display context. Refreshed on demand by cite_enrich worker.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS courtlistener_opinions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cl_opinion_id            bigint UNIQUE NOT NULL,               -- CourtListener opinion PK
  cl_cluster_id            bigint,
  case_name                text,
  court_id                 text,                                 -- CL court slug, e.g. 'wis'
  jurisdiction             text,                                 -- 'WI', 'US', '7th'
  date_filed               date,
  reporter                 text,                                 -- 'Wis.2d', 'F.3d', etc.
  volume                   text,
  page                     text,
  citation_canonical       text,                                 -- e.g. '123 Wis.2d 456'
  citation_url             text,                                 -- CL absolute URL
  holding_summary          text,                                 -- optional: filled by CL semantic search
  fetched_at               timestamptz NOT NULL DEFAULT now(),
  raw_cl_json              jsonb NOT NULL DEFAULT '{}'           -- full CL API response
);

CREATE INDEX IF NOT EXISTS cl_opinions_court_idx  ON courtlistener_opinions(court_id);
CREATE INDEX IF NOT EXISTS cl_opinions_date_idx   ON courtlistener_opinions(date_filed);
CREATE INDEX IF NOT EXISTS cl_opinions_reporter_idx ON courtlistener_opinions(reporter, volume, page);

-- ----------------------------------------------------------------------------
-- legal_citations: one row per citation extracted from a chunk.
-- Eyecite is the extraction engine; cite_enrich enriches with CL data.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS legal_citations (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Source
  chunk_id                 uuid NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
  document_id              uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  matter_id                uuid REFERENCES matters(id),

  -- Raw eyecite output
  raw                      text NOT NULL,                        -- verbatim citation string
  citation_type            text NOT NULL CHECK (citation_type IN (
                             'full', 'short', 'supra', 'id', 'unknown'
                           )),
  reporter                 text,
  volume                   text,
  page                     text,
  year                     int,
  pin_cite                 text,                                 -- pinpoint page, if any

  -- Normalized / resolved
  canonical                text,                                 -- 'volume reporter page'
  cl_opinion_id            bigint REFERENCES courtlistener_opinions(cl_opinion_id),
  resolution_status        text NOT NULL DEFAULT 'unresolved' CHECK (resolution_status IN (
                             'unresolved', 'resolved', 'not_found', 'ambiguous'
                           )),
  resolved_at              timestamptz,

  -- Extraction metadata
  extractor_version        text NOT NULL DEFAULT '2.x',
  char_offset_start        int,                                  -- offset in chunk.text
  char_offset_end          int,

  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS legal_citations_chunk_idx    ON legal_citations(chunk_id);
CREATE INDEX IF NOT EXISTS legal_citations_doc_idx      ON legal_citations(document_id);
CREATE INDEX IF NOT EXISTS legal_citations_matter_idx   ON legal_citations(matter_id);
CREATE INDEX IF NOT EXISTS legal_citations_reporter_idx ON legal_citations(reporter, volume, page);
CREATE INDEX IF NOT EXISTS legal_citations_cl_idx       ON legal_citations(cl_opinion_id)
  WHERE cl_opinion_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS legal_citations_status_idx   ON legal_citations(resolution_status)
  WHERE resolution_status = 'unresolved';

-- Unique: one eyecite extraction per (chunk, raw text) — idempotent re-runs
CREATE UNIQUE INDEX IF NOT EXISTS legal_citations_idempotent_idx
  ON legal_citations(chunk_id, raw);

-- ----------------------------------------------------------------------------
-- citation_graph: edges between opinions referenced in Meridian-Cannon.
-- Populated when two legal_citations in the same matter reference the
-- same pair of cl_opinion_ids.  Enables JurisRank-style authority scoring.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS citation_graph_edges (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  citing_opinion_id        bigint NOT NULL REFERENCES courtlistener_opinions(cl_opinion_id),
  cited_opinion_id         bigint NOT NULL REFERENCES courtlistener_opinions(cl_opinion_id),
  matter_id                uuid REFERENCES matters(id),
  edge_weight              float NOT NULL DEFAULT 1.0,
  created_at               timestamptz NOT NULL DEFAULT now(),
  UNIQUE (citing_opinion_id, cited_opinion_id, matter_id)
);

CREATE INDEX IF NOT EXISTS cge_citing_idx ON citation_graph_edges(citing_opinion_id);
CREATE INDEX IF NOT EXISTS cge_cited_idx  ON citation_graph_edges(cited_opinion_id);
