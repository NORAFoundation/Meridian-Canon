-- ============================================================================
-- reset_data.sql — clear ingested data for a clean test run.
--
-- Preserves:
--   * actors (system + owner placeholder)
--   * matters
--   * parties (the 'Self' party + AI synthetic parties)
--   * redaction_grounds_lookup
--   * Schema itself
--
-- Wipes:
--   * everything ingested via workers (documents, chunks, embeddings,
--     emails, messages, attachments, recordings, transactions, etc.)
--   * sources beyond seed (we leave matter+parties; sources rebuild)
--   * jobs, audit_log, transformations
--
-- Run as superuser/service_role.
-- ============================================================================

BEGIN;

-- Children first.  TRUNCATE ... CASCADE handles FK chains.
TRUNCATE TABLE
  embeddings,
  entity_mentions,
  entity_relationships,
  entities,
  classifications,
  tag_assignments,
  tags,
  attachment_relations,
  evidentiary_roles,
  chunks,
  document_versions,
  document_acquisitions,

  email_recipients,
  emails,
  message_associations,
  ai_chat_metadata,
  ai_chat_contexts,
  voicemail_metadata,
  call_events,
  messages,
  chat_members,
  chats,

  diarization_segments,
  transcript_revisions,
  transcripts,
  recordings,

  docket_snapshots,
  docket_entries,
  court_cases,

  p2p_transfers,
  transactions,
  financial_statements,
  financial_account_owners,
  financial_accounts,

  cdr_locations,
  cdrs,
  cdr_subscriber_lines,

  device_telemetry_query_jobs,
  tracking_disclosures,
  activity_events,
  social_posts,
  notes,
  browser_history,
  account_sign_ins,
  bluetooth_encounters,
  wifi_associations,
  workout_routes,
  health_records,
  place_observations,
  location_pings,
  device_events,
  devices,

  withheld_documents,
  redactions,
  privilege_assertions,
  legal_holds,

  production_redactions,
  production_documents,
  production_recipients,
  productions,
  records_requests,
  export_components,
  export_bundles,
  acquisitions,

  documents,
  sources,

  corroboration_links,
  transformations,
  jobs,
  audit_log
RESTART IDENTITY CASCADE;

COMMIT;

-- Sanity: confirm seeds survived.
DO $$
BEGIN
  IF (SELECT count(*) FROM actors) < 2 THEN
    RAISE EXCEPTION 'Seed actors missing after reset!';
  END IF;
  IF (SELECT count(*) FROM matters) < 1 THEN
    RAISE EXCEPTION 'Seed matter missing after reset!';
  END IF;
  IF (SELECT count(*) FROM parties) < 1 THEN
    RAISE EXCEPTION 'Seed parties missing after reset!';
  END IF;
  IF (SELECT count(*) FROM redaction_grounds_lookup) < 20 THEN
    RAISE EXCEPTION 'Seed redaction grounds missing after reset!';
  END IF;
  RAISE NOTICE 'Reset complete; seeds intact.';
END $$;
