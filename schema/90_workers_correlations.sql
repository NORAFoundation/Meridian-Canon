-- ============================================================================
-- 90_workers_correlations.sql
-- Worker job queue, transformations (audit of derivations applied to
-- documents/chunks), corroboration links across event types.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- jobs: simple Postgres-based queue using SELECT FOR UPDATE SKIP LOCKED.
-- ----------------------------------------------------------------------------

CREATE TABLE jobs (
  id                  bigserial PRIMARY KEY,
  kind                text NOT NULL,                                 -- 'gmail_fetch' | 'imessage_acquire' | etc.
  payload             jsonb NOT NULL DEFAULT '{}',
  state               text NOT NULL DEFAULT 'queued' CHECK (state IN (
                        'queued', 'running', 'succeeded', 'failed',
                        'dead_letter', 'cancelled'
                      )),
  priority            int NOT NULL DEFAULT 100,                      -- lower = higher priority
  attempts            int NOT NULL DEFAULT 0,
  max_attempts        int NOT NULL DEFAULT 5,
  run_after           timestamptz NOT NULL DEFAULT now(),
  locked_by           text,
  locked_until        timestamptz,
  last_error          text,
  enqueued_at         timestamptz NOT NULL DEFAULT now(),
  started_at          timestamptz,
  completed_at        timestamptz,
  parent_job_id       bigint REFERENCES jobs(id)
);

CREATE INDEX jobs_pull_idx ON jobs(state, run_after, priority)
  WHERE state IN ('queued');
CREATE INDEX jobs_kind_idx ON jobs(kind, state);
CREATE INDEX jobs_parent_idx ON jobs(parent_job_id) WHERE parent_job_id IS NOT NULL;

-- Convenience function: claim next job of a kind.
CREATE OR REPLACE FUNCTION jobs_claim_next(p_kind text, p_locker text, p_lease_seconds int DEFAULT 300)
RETURNS jobs AS $$
DECLARE
  j jobs;
BEGIN
  UPDATE jobs SET
    state = 'running',
    locked_by = p_locker,
    locked_until = now() + (p_lease_seconds || ' seconds')::interval,
    attempts = attempts + 1,
    started_at = coalesce(started_at, now())
  WHERE id = (
    SELECT id FROM jobs
    WHERE kind = p_kind
      AND state = 'queued'
      AND run_after <= now()
    ORDER BY priority ASC, enqueued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  RETURNING * INTO j;
  RETURN j;
END;
$$ LANGUAGE plpgsql;

-- AUDIT-FIX (HIGH-5): dead-letter / stale-lease sweep.
-- A worker that crashes mid-job leaves its row in state='running' with a
-- locked_until in the past; jobs_claim_next only pulls 'queued' rows, so
-- the work is silently stranded forever. This sweep reclaims expired
-- leases: rows with remaining attempts are re-queued; rows that have
-- exhausted max_attempts are moved to 'dead_letter' for inspection.
-- Returns the number of rows that were dead-lettered.
--
-- Schedule via pg_cron, e.g. (run once as a privileged role):
--   SELECT cron.schedule('jobs_sweep_stale', '* * * * *', $$SELECT jobs_sweep_stale()$$);
CREATE OR REPLACE FUNCTION jobs_sweep_stale() RETURNS int AS $$
DECLARE
  dead_count int;
BEGIN
  -- Re-queue reclaimable stale jobs (lease expired, attempts remain).
  UPDATE jobs SET
    state = 'queued',
    locked_by = NULL,
    locked_until = NULL,
    run_after = now()
  WHERE state = 'running'
    AND locked_until < now()
    AND attempts < max_attempts;

  -- Dead-letter the exhausted ones (lease expired, no attempts left).
  WITH dead AS (
    UPDATE jobs SET
      state = 'dead_letter',
      locked_by = NULL,
      locked_until = NULL,
      completed_at = now(),
      last_error = coalesce(last_error, 'stale lease; max_attempts exhausted')
    WHERE state = 'running'
      AND locked_until < now()
      AND attempts >= max_attempts
    RETURNING 1
  )
  SELECT count(*) INTO dead_count FROM dead;

  RETURN dead_count;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- transformations: every derivation applied to a document or chunk.
-- "OCR'd version produced by tesseract 5.3.0 on date X"; "transcript v2
-- replaced v1 as canonical".  Append-only.
-- ----------------------------------------------------------------------------

CREATE TABLE transformations (
  id                  bigserial PRIMARY KEY,
  occurred_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
  resource_type       text NOT NULL,
  resource_id         uuid NOT NULL,
  transform_kind      text NOT NULL,                                 -- 'ocr', 'chunk', 'embed', 'transcribe', 'redact', 'rechunk'
  tool                text NOT NULL,                                 -- 'tesseract' | 'whisper' | 'unstructured' | etc.
  tool_version        text NOT NULL,
  parameters          jsonb NOT NULL DEFAULT '{}',
  input_hash          text,
  output_ref          text,                                          -- pointer to result (uri or row id)
  acquisition_id      uuid REFERENCES acquisitions(id),
  actor_id            uuid REFERENCES actors(id),
  job_id              bigint REFERENCES jobs(id),
  notes               text
);

CREATE INDEX transformations_resource_idx ON transformations(resource_type, resource_id);
CREATE INDEX transformations_kind_idx ON transformations(transform_kind, occurred_at);
CREATE INDEX transformations_job_idx ON transformations(job_id) WHERE job_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- corroboration_links: cross-references between events that mutually
-- support or contradict each other.  Materialized periodically by a
-- corroboration_indexer worker (rules listed in design notes).  Each
-- link carries an evidence JSONB explaining *why* it was linked, so the
-- inference is auditable and rebuttable.
-- ----------------------------------------------------------------------------

CREATE TABLE corroboration_links (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  primary_resource_type    text NOT NULL,
  primary_resource_id      uuid NOT NULL,
  corroborator_type        text NOT NULL,
  corroborator_id          uuid NOT NULL,
  relationship             text NOT NULL CHECK (relationship IN (
                             'time_proximity', 'amount_match', 'party_match',
                             'content_match', 'location_match',
                             'contradicts', 'supports', 'reframes'
                           )),
  time_delta_s             int,
  confidence               numeric(4,3),
  evidence                 jsonb NOT NULL DEFAULT '{}',
  rule_name                text,                                     -- 'voicemail_to_cdr_5min' etc.
  rule_version             text,
  computed_at              timestamptz NOT NULL DEFAULT now(),
  reviewed                 boolean NOT NULL DEFAULT false,
  review_decision          text CHECK (review_decision IS NULL OR review_decision IN (
                             'accept', 'reject', 'needs_more'
                           )),
  reviewed_by_actor        uuid REFERENCES actors(id),
  reviewed_at              timestamptz
);

CREATE INDEX corrob_primary_idx ON corroboration_links(primary_resource_type, primary_resource_id);
CREATE INDEX corrob_corrob_idx ON corroboration_links(corroborator_type, corroborator_id);
CREATE INDEX corrob_relationship_idx ON corroboration_links(relationship);
CREATE INDEX corrob_unreviewed_idx ON corroboration_links(matter_id) WHERE NOT reviewed;
