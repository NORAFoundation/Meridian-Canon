-- ============================================================================
-- 30_documents.sql
-- Documents (bytes), versions, attachment relations, evidentiary roles,
-- chunks, embeddings, entities, mentions, tags, classifications.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- documents: identified by content hash.  One row per unique byte sequence.
-- Many acquisitions may produce the same hash (the same PDF arrived three
-- different ways); each is its own acquisition row but all share one
-- documents row.  This is what enables "every appearance of this document"
-- queries.
-- ----------------------------------------------------------------------------

CREATE TABLE documents (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  sha256                   text NOT NULL UNIQUE,
  byte_size                bigint NOT NULL,
  declared_mime_type       text,
  detected_mime_type       text,
  detected_format_family   text,                  -- 'pdf' | 'office_doc' | 'image' | etc.
  modality                 text CHECK (modality IS NULL OR modality IN (
                             'email_native', 'sms_thread_export', 'pdf_native',
                             'pdf_image_only', 'office_doc', 'spreadsheet',
                             'slides', 'image', 'audio', 'video', 'archive',
                             'rfc822_eml', 'calendar_ics', 'vcard', 'iwork',
                             'transcript_text', 'webpage', 'plain_text',
                             'json_export', 'xml_export', 'database', 'other'
                           )),
  storage_uri              text NOT NULL,         -- where the bytes live
  declared_filename        text,
  language                 text,                  -- 'en', 'es', etc.
  page_count               int,
  ocr_status               text CHECK (ocr_status IN (
                             'not_needed', 'pending', 'done', 'failed', 'partial'
                           )),
  perceptual_hash          text,                  -- pHash for images/dedup
  evidentiary_pii_tier     text NOT NULL DEFAULT 'internal'
                             CHECK (evidentiary_pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  encryption_blocked       boolean NOT NULL DEFAULT false,
  parser_status            text NOT NULL DEFAULT 'pending' CHECK (parser_status IN (
                             'pending', 'in_progress', 'parsed', 'unsupported',
                             'corrupt', 'deferred', 'blocked'
                           )),
  parser_version           text,
  first_seen_at            timestamptz NOT NULL DEFAULT now(),
  notes                    text,
  CHECK (length(sha256) = 64)
);

CREATE INDEX documents_matter_idx ON documents(matter_id);
CREATE INDEX documents_format_idx ON documents(detected_format_family);
CREATE INDEX documents_phash_idx ON documents(perceptual_hash) WHERE perceptual_hash IS NOT NULL;

-- ----------------------------------------------------------------------------
-- Forward-FK fixups deferred from earlier files.
-- ----------------------------------------------------------------------------

ALTER TABLE counsel_relationships
  ADD CONSTRAINT counsel_engagement_doc_fk
  FOREIGN KEY (signed_engagement_doc_id) REFERENCES documents(id);

ALTER TABLE records_requests
  ADD CONSTRAINT records_request_cover_doc_fk
  FOREIGN KEY (cover_letter_doc_id) REFERENCES documents(id);

ALTER TABLE productions
  ADD CONSTRAINT productions_cover_doc_fk
  FOREIGN KEY (cover_letter_doc_id) REFERENCES documents(id);

-- ----------------------------------------------------------------------------
-- documents-to-acquisitions: many-to-many (same hash, multiple fetch events).
-- ----------------------------------------------------------------------------

CREATE TABLE document_acquisitions (
  document_id     uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  acquisition_id  uuid NOT NULL REFERENCES acquisitions(id) ON DELETE CASCADE,
  PRIMARY KEY (document_id, acquisition_id)
);

CREATE INDEX doc_acq_acq_idx ON document_acquisitions(acquisition_id);

-- ----------------------------------------------------------------------------
-- document_versions: redacted copy, OCR'd derivative, password-removed,
-- bates-stamped versions.  The native, unaltered original is the document
-- row itself; versions are derivatives with their own bytes + hash.
-- ----------------------------------------------------------------------------

CREATE TABLE document_versions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id     uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  version_kind    text NOT NULL CHECK (version_kind IN (
                    'native', 'ocr_text', 'redacted', 'bates_stamped',
                    'image_renditions', 'normalized_pdf', 'extracted_attachments_only',
                    'translated', 'transcoded'
                  )),
  sha256          text NOT NULL,
  byte_size       bigint NOT NULL,
  storage_uri     text NOT NULL,
  produced_by     text,                            -- worker name + version
  produced_at     timestamptz NOT NULL DEFAULT now(),
  parent_version_id uuid REFERENCES document_versions(id),
  notes           text,
  CHECK (length(sha256) = 64)
);

CREATE INDEX document_versions_doc_idx ON document_versions(document_id);
CREATE INDEX document_versions_kind_idx ON document_versions(document_id, version_kind);

-- ----------------------------------------------------------------------------
-- attachment_relations: ties messages → attached documents.  The same
-- document attached to many messages is many rows here; one row per
-- *appearance*.  Each row is itself an evidentiary event (a transmission).
-- The actual messages table is defined in 40_communications.sql; we
-- reference it loosely via message_id with FK added later.
-- ----------------------------------------------------------------------------

CREATE TABLE attachment_relations (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id               uuid NOT NULL,           -- FK added in 40_communications.sql
  message_kind             text NOT NULL,           -- 'email' | 'message' (denormalized for routing)
  document_id              uuid NOT NULL REFERENCES documents(id),
  position                 int,                     -- order in MIME tree / message
  parent_attachment_id     uuid REFERENCES attachment_relations(id),  -- nesting (zip, eml-in-eml)
  content_disposition      text CHECK (content_disposition IN (
                             'attachment', 'inline', 'related'
                           )),
  declared_mime_type       text,
  detected_mime_type       text,
  declared_filename        text,
  content_id               text,                    -- cid: for inline images
  size_bytes               bigint,
  parser_version           text,
  parsed_status            text NOT NULL DEFAULT 'ok' CHECK (parsed_status IN (
                             'ok', 'blocked', 'corrupt', 'deferred', 'recursed'
                           )),
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX attachment_message_idx ON attachment_relations(message_id);
CREATE INDEX attachment_document_idx ON attachment_relations(document_id);
CREATE INDEX attachment_parent_idx ON attachment_relations(parent_attachment_id)
  WHERE parent_attachment_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- evidentiary_roles: many-to-many tags on (document, originating-acquisition)
-- for different evidentiary purposes.  A document can simultaneously be
-- transmission_evidence (because it was attached to a message) and
-- content_evidence (because the substance is itself a fact).
-- ----------------------------------------------------------------------------

CREATE TABLE evidentiary_roles (
  document_id                       uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  role                              text NOT NULL CHECK (role IN (
                                      'transmission_evidence', 'content_evidence',
                                      'native_capture', 'public_record',
                                      'expert_input', 'demonstrative',
                                      'party_admission_candidate',
                                      'strategy_workproduct_candidate',
                                      'authentication_artifact'
                                    )),
  established_by_acquisition_id     uuid REFERENCES acquisitions(id),
  notes                             text,
  added_at                          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (document_id, role, established_by_acquisition_id)
);

CREATE INDEX evidentiary_roles_role_idx ON evidentiary_roles(role);

-- ----------------------------------------------------------------------------
-- chunks: section-aware, modality-specific.  Each chunk has a parent document
-- and may have a parent_chunk for hierarchical sections.  chunk_text_tsv is
-- a generated tsvector for FTS.
-- ----------------------------------------------------------------------------

CREATE TABLE chunks (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id         uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  parent_chunk_id     uuid REFERENCES chunks(id),
  chunker             text NOT NULL,             -- 'pdf_layout' | 'email_mime' | 'message_window' | etc.
  chunker_version     text NOT NULL,
  modality            text NOT NULL,             -- per chunks-modality vocab
  ordinal             int NOT NULL,              -- order within the document
  section_path        text,                      -- '1/2.3/4' or 'Introduction > Background'
  page_range          int4range,                 -- for paginated sources
  bates_range         text,                      -- '00481-00485' if known
  char_offsets        int4range,                 -- offsets into the *normalized* text
  text                text NOT NULL,
  text_tsv            tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED,
  attachment_relation_id uuid REFERENCES attachment_relations(id),  -- if from an attachment
  message_id          uuid,                      -- FK added in 40_communications
  recording_id        uuid,                      -- FK added in 50_recordings
  start_ms            int,                       -- for audio/video
  end_ms              int,
  speaker_label       text,                      -- for transcripts
  metadata            jsonb NOT NULL DEFAULT '{}',
  pii_tier            text NOT NULL DEFAULT 'internal'
                        CHECK (pii_tier IN (
                          'public', 'low', 'internal', 'sensitive',
                          'privileged', 'work_product'
                        )),
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX chunks_document_ord_idx ON chunks(document_id, ordinal);
CREATE INDEX chunks_parent_idx ON chunks(parent_chunk_id);
CREATE INDEX chunks_message_idx ON chunks(message_id) WHERE message_id IS NOT NULL;
CREATE INDEX chunks_recording_idx ON chunks(recording_id) WHERE recording_id IS NOT NULL;
CREATE INDEX chunks_attachment_idx ON chunks(attachment_relation_id)
  WHERE attachment_relation_id IS NOT NULL;
CREATE INDEX chunks_text_tsv_idx ON chunks USING GIN (text_tsv);
CREATE INDEX chunks_metadata_idx ON chunks USING GIN (metadata);

-- ----------------------------------------------------------------------------
-- embeddings: pgvector.  Multiple models can coexist over time (so you can
-- re-embed without losing history).  Default vector dimension is 1024 to
-- match the chosen primary model: BAAI/bge-large-en-v1.5 (local, MIT
-- licensed, top-tier MTEB).  bge-m3 is a 1024-dim drop-in replacement if
-- you need multilingual / hybrid sparse+dense later.
--
-- If you ever switch to a different-dim model (e.g., 768 for nomic, 3072
-- for OpenAI text-embedding-3-large), add a sibling table with a different
-- vector column rather than altering this one — pgvector dim is fixed
-- per column.
-- ----------------------------------------------------------------------------

CREATE TABLE embeddings (
  chunk_id            uuid NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
  model_name          text NOT NULL,
  model_version       text NOT NULL,
  dim                 int NOT NULL,
  vector              vector(1024) NOT NULL,    -- bge-large-en-v1.5 / bge-m3
  computed_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chunk_id, model_name, model_version)
);

-- HNSW index for approximate nearest-neighbor (pgvector >= 0.5).
-- m=16, ef_construction=64 is a sane default for ~hundreds of K rows.
CREATE INDEX embeddings_hnsw_idx
  ON embeddings USING hnsw (vector vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

-- ----------------------------------------------------------------------------
-- entities: canonical real-world referents extracted via NER + resolution.
-- A "person" entity may be referenced by many handles, mentioned in many
-- chunks.  An entity is *not* the same as a party — parties are formal
-- legal participants; entities are anyone or anything mentioned anywhere.
-- ----------------------------------------------------------------------------

CREATE TABLE entities (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id       uuid REFERENCES matters(id),
  kind            text NOT NULL CHECK (kind IN (
                    'person', 'organization', 'location', 'date',
                    'monetary_amount', 'phone_number', 'email_address',
                    'url', 'event', 'identifier', 'vehicle', 'asset',
                    'court', 'case_citation', 'statute', 'other'
                  )),
  canonical_label text NOT NULL,
  aliases         text[] NOT NULL DEFAULT '{}',
  metadata        jsonb NOT NULL DEFAULT '{}',
  resolved_party_id uuid REFERENCES parties(id),    -- if the entity IS a party
  notes           text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX entities_kind_idx ON entities(kind);
CREATE INDEX entities_label_trgm_idx ON entities USING GIN (canonical_label gin_trgm_ops);
CREATE INDEX entities_party_idx ON entities(resolved_party_id) WHERE resolved_party_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- entity_mentions: per-chunk occurrences of entities.  Confidence + the NER
-- model + span lets us re-derive on model upgrades.
-- ----------------------------------------------------------------------------

CREATE TABLE entity_mentions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  chunk_id        uuid NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
  entity_id       uuid NOT NULL REFERENCES entities(id),
  span_start      int NOT NULL,
  span_end        int NOT NULL,
  surface_text    text NOT NULL,
  confidence      numeric(4,3),
  ner_model       text NOT NULL,
  ner_model_version text NOT NULL,
  CHECK (span_end > span_start),
  CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE INDEX mentions_entity_idx ON entity_mentions(entity_id);
CREATE INDEX mentions_chunk_idx ON entity_mentions(chunk_id);

-- ----------------------------------------------------------------------------
-- entity_relationships: derived graph between entities.  Allows building
-- person → person, person → organization, person → location etc. networks.
-- ----------------------------------------------------------------------------

CREATE TABLE entity_relationships (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  src_entity_id   uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  dst_entity_id   uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  relationship    text NOT NULL,                -- 'employed_by', 'parent_of', 'contracted_with', etc.
  confidence      numeric(4,3),
  evidence        jsonb NOT NULL DEFAULT '{}',  -- chunk_ids, citations, etc.
  asserted_by     text,                          -- 'extraction_v1' | 'manual'
  asserted_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX entity_rel_src_idx ON entity_relationships(src_entity_id);
CREATE INDEX entity_rel_dst_idx ON entity_relationships(dst_entity_id);

-- ----------------------------------------------------------------------------
-- tags: free-form labels.  Manual or rule-derived.
-- ----------------------------------------------------------------------------

CREATE TABLE tags (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id       uuid REFERENCES matters(id),
  label           text NOT NULL,
  color           text,
  description     text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (matter_id, label)
);

CREATE TABLE tag_assignments (
  tag_id          uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  resource_type   text NOT NULL,                  -- 'document' | 'message' | 'chunk' | 'recording' | 'transaction'
  resource_id     uuid NOT NULL,
  assigned_by_actor uuid REFERENCES actors(id),
  assigned_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tag_id, resource_type, resource_id)
);

CREATE INDEX tag_assignments_resource_idx ON tag_assignments(resource_type, resource_id);

-- ----------------------------------------------------------------------------
-- classifications: predicted + reviewed labels (privilege, responsiveness,
-- issue codes, etc.) with a separate "reviewed" flag.  Distinct from tags
-- because classifications are first-class with confidence + model history.
-- ----------------------------------------------------------------------------

CREATE TABLE classifications (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_type       text NOT NULL,              -- 'document' | 'chunk' | 'message'
  resource_id         uuid NOT NULL,
  scheme              text NOT NULL,              -- 'privilege' | 'responsiveness' | 'issue_code' | 'sentiment'
  label               text NOT NULL,
  confidence          numeric(4,3),
  model               text,
  model_version       text,
  reviewed            boolean NOT NULL DEFAULT false,
  reviewed_by_actor   uuid REFERENCES actors(id),
  reviewed_at         timestamptz,
  notes               text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX classifications_resource_idx ON classifications(resource_type, resource_id);
CREATE INDEX classifications_scheme_idx ON classifications(scheme, label);

-- ----------------------------------------------------------------------------
-- production_documents and production_redactions (deferred from 20_provenance
-- because they reference documents).
-- ----------------------------------------------------------------------------

CREATE TABLE production_documents (
  production_id          uuid NOT NULL REFERENCES productions(id) ON DELETE CASCADE,
  document_id            uuid NOT NULL REFERENCES documents(id),
  document_version_id    uuid REFERENCES document_versions(id),  -- redacted version produced
  bates_begin            int,
  bates_end              int,
  native_path            text,
  image_path             text,
  text_path              text,
  load_file_row          jsonb,
  PRIMARY KEY (production_id, document_id)
);

CREATE INDEX production_docs_doc_idx ON production_documents(document_id);

-- Redactions made specifically for a production are frozen with that
-- production; if the master copy is later re-redacted, this snapshot remains.
CREATE TABLE production_redactions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  production_id       uuid NOT NULL REFERENCES productions(id) ON DELETE CASCADE,
  document_id         uuid NOT NULL REFERENCES documents(id),
  page                int,
  bbox                jsonb,                          -- {x, y, w, h} or coordinate list
  char_range          int4range,
  reason              text NOT NULL,
  reason_statute_cite text,                           -- 'Wis. Stat. § 48.396', 'HIPAA', etc.
  redacted_text_replacement text,                     -- "[REDACTED – CHILD WELFARE]"
  applied_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX production_redactions_doc_idx ON production_redactions(document_id);
