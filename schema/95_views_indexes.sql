-- ============================================================================
-- 95_views_indexes.sql
-- Cross-channel views for retrieval, lineage views for citation rendering,
-- privilege-log generator, additional indexes.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- comms_unified: every communication regardless of channel.  Drives "every
-- communication with X between dates A and B" queries without per-table
-- branching at query time.
-- ----------------------------------------------------------------------------

CREATE VIEW comms_unified AS
  SELECT
    e.id                    AS comm_id,
    'email'::text           AS comm_kind,
    e.matter_id,
    e.thread_canonical_id   AS thread_id,
    e.from_handle           AS sender_handle,
    NULL::text[]            AS recipient_handles,
    e.date_sent             AS occurred_at,
    e.subject               AS subject,
    e.body_text             AS body,
    e.has_attachments,
    e.pii_tier,
    e.document_id
  FROM emails e
UNION ALL
  SELECT
    m.id                    AS comm_id,
    m.kind                  AS comm_kind,
    m.matter_id,
    m.chat_id::text         AS thread_id,
    m.sender_handle,
    m.recipient_handles,
    m.sent_at               AS occurred_at,
    NULL                    AS subject,
    m.body_text             AS body,
    m.has_attachments,
    m.pii_tier,
    NULL::uuid              AS document_id
  FROM messages m;

-- ----------------------------------------------------------------------------
-- document_lineage: full provenance chain for a document, suitable for
-- citation rendering ("attached to email from X to Y on date Z, forwarded
-- by Y to Z on date W, originally captured via acquisition Q").
-- ----------------------------------------------------------------------------

CREATE VIEW document_lineage AS
  SELECT
    d.id                    AS document_id,
    d.sha256,
    d.declared_filename,
    d.modality,
    da.acquisition_id,
    a.fetched_at,
    a.method                AS acquisition_method,
    a.legal_basis,
    s.kind                  AS source_kind,
    s.label                 AS source_label,
    s.party_id              AS source_party_id,
    ar.id                   AS attachment_relation_id,
    ar.message_id           AS appearing_in_message_id,
    ar.message_kind         AS appearing_in_kind
  FROM documents d
  LEFT JOIN document_acquisitions da ON da.document_id = d.id
  LEFT JOIN acquisitions a ON a.id = da.acquisition_id
  LEFT JOIN sources s ON s.id = a.source_id
  LEFT JOIN attachment_relations ar ON ar.document_id = d.id;

-- ----------------------------------------------------------------------------
-- privilege_log_view: per-production privilege log, formatted for export.
-- ----------------------------------------------------------------------------

CREATE VIEW privilege_log_view AS
  SELECT
    p.id                    AS production_id,
    p.production_date,
    p.bates_prefix,
    w.id                    AS withheld_id,
    w.document_id,
    w.description_for_log,
    w.date_of_document,
    w.authors,
    w.recipients,
    w.subject,
    pa.privilege_type,
    pa.basis,
    pa.shared_with_counsel_id,
    pa.shared_with_expert_id
  FROM withheld_documents w
  JOIN productions p ON p.id = w.production_id
  JOIN privilege_assertions pa ON pa.id = w.privilege_assertion_id;

-- ----------------------------------------------------------------------------
-- timeline_unified: events in chronological order across channels.
-- Useful as the primary feed for review and corroboration UIs.
-- ----------------------------------------------------------------------------

CREATE VIEW timeline_unified AS
  SELECT 'email'::text AS kind, id AS resource_id, matter_id,
         date_sent AS occurred_at, from_handle AS actor, subject AS summary
  FROM emails WHERE date_sent IS NOT NULL
UNION ALL
  SELECT 'message', id, matter_id, sent_at, sender_handle,
         left(coalesce(body_text, ''), 200)
  FROM messages WHERE sent_at IS NOT NULL
UNION ALL
  SELECT 'call', id, matter_id, initiated_at, caller_handle,
         platform || ' call ' || coalesce(outcome, '')
  FROM call_events WHERE initiated_at IS NOT NULL
UNION ALL
  SELECT 'cdr', c.id, NULL, c.initiated_at, c.peer_number,
         c.type || ' ' || c.direction
  FROM cdrs c
UNION ALL
  SELECT 'transaction', t.id, fa.matter_id, t.posted_at,
         t.counterparty_handle,
         t.direction || ' ' || (t.amount_minor::numeric / 100)::text || ' ' || t.currency
  FROM transactions t
  JOIN financial_accounts fa ON fa.id = t.account_id
  WHERE t.posted_at IS NOT NULL
UNION ALL
  SELECT 'docket', de.id, cc.matter_id, (de.entry_date::timestamp AT TIME ZONE 'UTC'),
         de.filing_party, de.entry_type || ': ' || coalesce(de.description, '')
  FROM docket_entries de JOIN court_cases cc ON cc.id = de.court_case_id
  WHERE de.entry_date IS NOT NULL
UNION ALL
  SELECT 'sign_in', si.id, NULL, si.signed_in_at, si.service, si.result
  FROM account_sign_ins si
UNION ALL
  SELECT 'location', lp.id, NULL, lp.observed_at, lp.source_kind,
         coalesce(lp.inferred_place, lp.lat || ',' || lp.lng)
  FROM location_pings lp;

-- ----------------------------------------------------------------------------
-- Additional indexes — primarily timestamp/composite indexes that benefit
-- the timeline view and corroboration queries.
-- ----------------------------------------------------------------------------

CREATE INDEX cdrs_peer_time_idx ON cdrs(peer_number, initiated_at);
CREATE INDEX transactions_posted_amount_idx ON transactions(posted_at, amount_minor);
CREATE INDEX messages_sender_sent_idx ON messages(sender_handle, sent_at);
CREATE INDEX emails_thread_date_idx ON emails(thread_canonical_id, date_sent);

-- For typical retrieval: hybrid BM25 + vector + filter by matter and time
-- window.  Embeddings already indexed via HNSW; tsvector via GIN.

-- For payload JSONB fields with frequent path queries, add jsonb_path_ops
-- GIN indexes selectively (commented; uncomment per-table as needed):
-- CREATE INDEX device_events_payload_path_idx ON device_events
--   USING GIN (payload jsonb_path_ops);
