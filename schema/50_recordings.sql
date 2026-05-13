-- ============================================================================
-- 50_recordings.sql
-- Audio recordings, transcripts (with multiple authority levels coexisting),
-- transcript revisions (human corrections), diarization segments.
-- ============================================================================

CREATE TABLE recordings (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  document_id              uuid NOT NULL REFERENCES documents(id),  -- the audio bytes
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  kind                     text NOT NULL CHECK (kind IN (
                             'voice_memo', 'voicemail', 'phone_call',
                             'court_hearing', 'deposition', 'meeting',
                             'conversation', 'interview', 'lecture', 'other'
                           )),
  recorded_at              timestamptz,
  duration_s               numeric(10,3),
  sample_rate_hz           int,
  channels                 int,
  codec                    text,
  bitrate_bps              int,
  device_id                uuid,                                     -- FK added in 80_telemetry
  jurisdiction_recorded_in text,                                     -- 'WI', 'MN', 'CA', etc.
  participant_jurisdictions text[],
  consent_basis            text CHECK (consent_basis IS NULL OR consent_basis IN (
                             'one_party_self', 'all_party_consent',
                             'court_authorized', 'public_proceeding',
                             'unknown', 'disputed'
                           )),
  device_creation_metadata jsonb NOT NULL DEFAULT '{}',              -- ffprobe / EXIF-like
  original_filename        text,
  authority                text NOT NULL DEFAULT 'working' CHECK (authority IN (
                             'official', 'working'
                           )),                                       -- official = court-reporter source
  pii_tier                 text NOT NULL DEFAULT 'sensitive'
                             CHECK (pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  ingested_at              timestamptz NOT NULL DEFAULT now(),
  notes                    text
);

CREATE INDEX recordings_matter_idx ON recordings(matter_id);
CREATE INDEX recordings_kind_idx ON recordings(kind);
CREATE INDEX recordings_recorded_at_idx ON recordings(recorded_at);
CREATE INDEX recordings_doc_idx ON recordings(document_id);

-- Wire up the deferred FKs from 40_communications.

ALTER TABLE messages
  ADD CONSTRAINT messages_recording_fk
  FOREIGN KEY (recording_id) REFERENCES recordings(id);

ALTER TABLE call_events
  ADD CONSTRAINT call_events_recording_fk
  FOREIGN KEY (recording_id) REFERENCES recordings(id);

-- chunks.recording_id was already declared in 30_documents but no FK yet.
ALTER TABLE chunks
  ADD CONSTRAINT chunks_recording_fk
  FOREIGN KEY (recording_id) REFERENCES recordings(id);

-- ----------------------------------------------------------------------------
-- transcripts: multiple per recording, distinguished by authority + model.
-- 'official' is the court-reporter or carrier-provided text; 'working' is
-- our generated version.  Chunks should derive from the highest-authority
-- transcript when available.
-- ----------------------------------------------------------------------------

CREATE TABLE transcripts (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recording_id        uuid NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  authority           text NOT NULL CHECK (authority IN ('official', 'working', 'carrier')),
  model               text,                                          -- 'whisper-large-v3' | 'apple_voicemail_transcription' | 'official'
  model_version       text,
  params              jsonb NOT NULL DEFAULT '{}',                   -- temperature, prompt, etc.
  language            text,
  full_text           text NOT NULL,
  full_text_tsv       tsvector GENERATED ALWAYS AS (
                        to_tsvector('english', full_text)
                      ) STORED,
  word_timing         jsonb,                                         -- [[word, start_ms, end_ms, conf], ...]
  mean_confidence     numeric(4,3),
  produced_at         timestamptz NOT NULL DEFAULT now(),
  source_acquisition_id uuid REFERENCES acquisitions(id),
  is_canonical        boolean NOT NULL DEFAULT false,                -- the version chunks derive from
  notes               text
);

CREATE INDEX transcripts_recording_idx ON transcripts(recording_id);
CREATE INDEX transcripts_authority_idx ON transcripts(recording_id, authority);
CREATE INDEX transcripts_canonical_idx ON transcripts(recording_id) WHERE is_canonical;
CREATE INDEX transcripts_text_tsv_idx ON transcripts USING GIN (full_text_tsv);

-- Only one canonical per recording at a time.
CREATE UNIQUE INDEX transcripts_one_canonical_per_recording
  ON transcripts(recording_id) WHERE is_canonical;

-- ----------------------------------------------------------------------------
-- transcript_revisions: human corrections.  Original raw model output is
-- preserved on transcripts.full_text; revisions are diffs / replacements
-- applied during review.  Each revision is itself an evidentiary act
-- (someone said "this should read X instead").
-- ----------------------------------------------------------------------------

CREATE TABLE transcript_revisions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  transcript_id       uuid NOT NULL REFERENCES transcripts(id) ON DELETE CASCADE,
  revised_by_actor    uuid REFERENCES actors(id),
  revised_at          timestamptz NOT NULL DEFAULT now(),
  diff_format         text NOT NULL CHECK (diff_format IN (
                        'span_replace', 'unified_diff', 'word_edit_list'
                      )),
  diff                jsonb NOT NULL,
  rationale           text
);

CREATE INDEX transcript_revisions_idx ON transcript_revisions(transcript_id, revised_at);

-- ----------------------------------------------------------------------------
-- diarization_segments: speaker turns.  Aligned with transcripts post hoc;
-- a transcript may have a 1:1 diarization or none.
-- ----------------------------------------------------------------------------

CREATE TABLE diarization_segments (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recording_id        uuid NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  transcript_id       uuid REFERENCES transcripts(id),
  start_ms            int NOT NULL,
  end_ms              int NOT NULL,
  speaker_label       text NOT NULL,                                  -- 'SPEAKER_00' | 'judge' | resolved name
  resolved_party_id   uuid REFERENCES parties(id),                    -- if speaker resolved
  confidence          numeric(4,3),
  diarization_model   text NOT NULL,
  diarization_model_version text NOT NULL,
  CHECK (end_ms > start_ms)
);

CREATE INDEX diarization_recording_idx ON diarization_segments(recording_id, start_ms);
CREATE INDEX diarization_speaker_idx ON diarization_segments(speaker_label);
CREATE INDEX diarization_party_idx ON diarization_segments(resolved_party_id)
  WHERE resolved_party_id IS NOT NULL;
