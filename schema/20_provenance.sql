-- ============================================================================
-- 20_provenance.sql
-- Sources, acquisitions (every fetch), records requests, productions,
-- export bundles (umbrella exports like Apple Privacy / Google Takeout).
--
-- This is the spine of chain of custody.  No document exists without an
-- acquisition; no acquisition without a source.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- sources: a provenance origin.  One row per logical origin we can attribute
-- to.  Examples: a Gmail account; a specific iPhone device's chat.db; a
-- bank's online banking portal; a court's CCAP page; an AI account.
-- ----------------------------------------------------------------------------

CREATE TABLE sources (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  party_id                 uuid REFERENCES parties(id),  -- whose data (if known)
  kind                     text NOT NULL,
                           -- 'gmail' | 'apple_mail' | 'imessage' | 'fb_messenger' |
                           -- 'voicemail_iphone' | 'voicemail_gvoice' | 'carrier_cdr' |
                           -- 'ccap' | 'courtlistener' | 'bank_statement' | 'plaid' |
                           -- 'venmo' | 'zelle' | 'cashapp' | 'paypal' |
                           -- 'apple_card' | 'apple_pay' | 'apple_cash' |
                           -- 'apple_privacy_export' | 'google_takeout' | 'facebook_dyi' |
                           -- 'ai_chat_chatgpt' | 'ai_chat_claude' | 'ai_chat_grok' |
                           -- 'audio_recording' | 'screenshot' | 'manual_import' |
                           -- 'iphone_backup' | 'macos_local' | 'third_party_production'
  label                    text NOT NULL,           -- human-readable
  external_account         text,                    -- 'me@gmail.com', '+15555551234', etc.
  default_evidentiary_role text CHECK (default_evidentiary_role IN (
                             'transmission_evidence', 'content_evidence',
                             'native_capture', 'public_record',
                             'expert_input', 'demonstrative',
                             'party_admission_candidate',
                             'strategy_workproduct_candidate'
                           )),
  default_pii_tier         text NOT NULL DEFAULT 'internal'
                             CHECK (default_pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  default_access_role_floor text CHECK (default_access_role_floor IN (
                             'owner', 'counsel', 'paralegal', 'expert', 'family'
                           )),
  notes                    text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sources_matter_idx ON sources(matter_id);
CREATE INDEX sources_kind_idx ON sources(kind);

-- ----------------------------------------------------------------------------
-- acquisitions: every individual fetch/import event.  Immutable.  Carries
-- the bytes-on-disk hash, the HTTP/SQL/API transaction record, the legal
-- basis for the acquisition, and points at the actor who performed it.
-- ----------------------------------------------------------------------------

CREATE TABLE acquisitions (
  id                            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id                     uuid NOT NULL REFERENCES sources(id),
  fetched_at                    timestamptz NOT NULL DEFAULT now(),
  fetched_by_actor_id           uuid REFERENCES actors(id),
  method                        text NOT NULL,
                                -- 'gmail_api' | 'imap_peek' | 'chat_db_backup' |
                                -- 'iphone_backup' | 'meta_dyi_export' |
                                -- 'apple_privacy_export' | 'google_takeout' |
                                -- 'csv_upload' | 'pdf_upload' | 'ccap_warc' |
                                -- 'plaid_oauth' | 'manual_entry' | 'subpoena_disc' |
                                -- 'foia' | 'open_records' | 'voluntary_production'
  legal_basis                   text NOT NULL DEFAULT 'self_access' CHECK (legal_basis IN (
                                  'self_access', 'consent', 'subpoena', 'court_order',
                                  'open_records', 'foia', 'voluntary_production',
                                  'plaid_oauth', 'statutory_disclosure'
                                )),
  authentication_artifact_ref   text,            -- pointer to custodian decl, etc.
  raw_storage_uri               text NOT NULL,    -- e.g., s3://.../raw/email/2024-03/{sha}.eml
  raw_byte_size                 bigint NOT NULL,
  raw_sha256                    text NOT NULL,    -- 64 hex chars
  raw_mime_type                 text,
  request_meta                  jsonb NOT NULL DEFAULT '{}',  -- API request, query, etc.
  response_meta                 jsonb NOT NULL DEFAULT '{}',  -- headers, status, etc.
  parser_version                text,
  parsed_at                     timestamptz,
  notes                         text,
  CHECK (length(raw_sha256) = 64)
);

CREATE INDEX acquisitions_source_idx ON acquisitions(source_id, fetched_at);
CREATE INDEX acquisitions_hash_idx ON acquisitions(raw_sha256);
CREATE INDEX acquisitions_method_idx ON acquisitions(method);

-- ----------------------------------------------------------------------------
-- records_requests: WI Open Records, FOIA, subpoenas, discovery requests.
-- Tracks the formal request lifecycle separately from individual acquisitions.
-- ----------------------------------------------------------------------------

CREATE TABLE records_requests (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid NOT NULL REFERENCES matters(id),
  request_kind             text NOT NULL CHECK (request_kind IN (
                             'wi_open_records', 'foia', 'subpoena_duces_tecum',
                             'discovery_request', 'rule_45_subpoena',
                             'voluntary_letter', 'other'
                           )),
  custodian_party_id       uuid REFERENCES parties(id),
  custodian_contact_text   text,
  statute_or_rule_cited    text,                    -- 'Wis. Stat. § 19.35', '5 U.S.C. § 552'
  requested_at             date NOT NULL,
  due_at                   date,
  description              text NOT NULL,
  status                   text NOT NULL DEFAULT 'open' CHECK (status IN (
                             'open', 'acknowledged', 'partial_response',
                             'fulfilled', 'denied', 'withdrawn', 'appealed'
                           )),
  fee_charged_cents        bigint,
  cover_letter_doc_id      uuid,                    -- FK added in 30_documents
  notes                    text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX records_requests_matter_idx ON records_requests(matter_id, requested_at);

-- ----------------------------------------------------------------------------
-- productions (outbound and inbound):
--   Outbound: documents you produce TO another party (opposing counsel, court).
--   Inbound:  documents another party produces TO you (DHS records, third-party).
-- The same table tracks both with `direction`.
-- A production is *frozen* on production_date — the snapshot of what was sent
-- never changes thereafter, even if the underlying documents are revised.
-- ----------------------------------------------------------------------------

CREATE TABLE productions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid NOT NULL REFERENCES matters(id),
  direction           text NOT NULL CHECK (direction IN ('outbound', 'inbound')),
  produced_by_party_id uuid REFERENCES parties(id),
  produced_to_party_id uuid REFERENCES parties(id),
  production_date     date NOT NULL,
  bates_prefix        text,
  bates_start         int,
  bates_end           int,
  format              text CHECK (format IN (
                        'native_only', 'image_only',
                        'native_image_text_load', 'concordance_dat_opt',
                        'relativity_dat', 'edrm_xml', 'pdf_bundle', 'mixed'
                      )),
  cover_letter_doc_id uuid,                          -- FK added in 30_documents
  hash_manifest_uri   text,                          -- file listing { path, sha256 }
  records_request_id  uuid REFERENCES records_requests(id),
  frozen_at           timestamptz NOT NULL DEFAULT now(),
  notes               text
);

CREATE INDEX productions_matter_dir_idx ON productions(matter_id, direction, production_date);

-- A production may go to multiple recipients (rare for outbound, common for
-- court filings where the court + each party gets a copy).
CREATE TABLE production_recipients (
  production_id        uuid NOT NULL REFERENCES productions(id) ON DELETE CASCADE,
  party_id             uuid NOT NULL REFERENCES parties(id),
  delivered_at         timestamptz,
  delivery_method      text,                        -- 'efile', 'email', 'mail', 'hand'
  acknowledgment_ref   text,                        -- bounce, signed receipt, etc.
  PRIMARY KEY (production_id, party_id)
);

-- production_documents and production_redactions are defined in 30_documents
-- after documents exists.

-- ----------------------------------------------------------------------------
-- export_bundles: umbrella exports (Apple Privacy, Google Takeout, FB DYI).
-- A bundle is one acquisition; the parts inside become components, each
-- routed to a sub-acquisition.
-- ----------------------------------------------------------------------------

CREATE TABLE export_bundles (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  acquisition_id      uuid NOT NULL REFERENCES acquisitions(id),
  platform            text NOT NULL CHECK (platform IN (
                        'apple_privacy', 'google_takeout', 'facebook_dyi',
                        'twitter_archive', 'microsoft_export', 'linkedin_export'
                      )),
  bundle_sha256       text NOT NULL,
  total_size_bytes    bigint NOT NULL,
  request_submitted_at timestamptz,
  delivered_at        timestamptz,
  unpacked_at         timestamptz,
  notes               text
);

CREATE INDEX export_bundles_acq_idx ON export_bundles(acquisition_id);

CREATE TABLE export_components (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id                uuid NOT NULL REFERENCES export_bundles(id) ON DELETE CASCADE,
  component_kind           text NOT NULL,
                           -- 'imessage' | 'mail' | 'maps_timeline' |
                           -- 'apple_card' | 'photos' | 'safari_history' | etc.
  source_path_in_archive   text NOT NULL,
  size_bytes               bigint,
  child_acquisition_id     uuid REFERENCES acquisitions(id),
  routed_to_worker         text,
  status                   text NOT NULL DEFAULT 'pending' CHECK (status IN (
                             'pending', 'routed', 'parsed', 'unsupported',
                             'failed', 'skipped'
                           )),
  notes                    text
);

CREATE INDEX export_components_bundle_idx ON export_components(bundle_id);
CREATE INDEX export_components_status_idx ON export_components(status);
