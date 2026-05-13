-- ============================================================================
-- 40_communications.sql
-- Emails (separate, MIME-rich), unified messages (sms/imessage/messenger/
-- ai_chat/voicemail), chats, message associations (replies/reactions),
-- AI-chat metadata, AI-chat contexts, call events, voicemail metadata.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- emails: kept separate from messages because of MIME, multi-recipient
-- envelopes, full Received chain, DKIM/auth headers, and recursive
-- nesting (forwarded .eml as attachments).
-- ----------------------------------------------------------------------------

CREATE TABLE emails (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  document_id              uuid NOT NULL REFERENCES documents(id),  -- the .eml bytes
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  message_id_header        text,                                     -- RFC822 Message-ID
  in_reply_to_header       text,                                     -- Message-ID of parent
  references_headers       text[],                                   -- thread chain
  thread_canonical_id      text,                                     -- derived from header graph
  parent_email_id          uuid REFERENCES emails(id),               -- for forwarded-as-attachment
  from_handle              text,
  reply_to_handle          text,
  subject                  text,
  date_sent                timestamptz,
  date_received            timestamptz,
  body_text                text,
  body_html_storage_uri    text,                                     -- HTML preserved separately
  body_text_tsv            tsvector GENERATED ALWAYS AS (
                             to_tsvector('english',
                               coalesce(subject, '') || ' ' || coalesce(body_text, ''))
                           ) STORED,
  full_headers_raw         text NOT NULL,                            -- unparsed headers blob
  authentication_results   text,                                     -- Authentication-Results header
  dkim_signatures          text[],                                   -- preserve verbatim
  spf_result               text,
  has_attachments          boolean NOT NULL DEFAULT false,
  is_encrypted             boolean NOT NULL DEFAULT false,
  encryption_kind          text,                                     -- 'smime' | 'pgp' | NULL
  account_label            text,                                     -- 'me@gmail.com' (which mailbox saw it)
  mailbox_labels           text[] NOT NULL DEFAULT '{}',             -- Gmail labels, IMAP folders
  is_draft                 boolean NOT NULL DEFAULT false,
  is_sent                  boolean,
  is_trash                 boolean NOT NULL DEFAULT false,
  is_spam                  boolean NOT NULL DEFAULT false,
  pii_tier                 text NOT NULL DEFAULT 'internal'
                             CHECK (pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  ingested_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX emails_matter_idx ON emails(matter_id);
CREATE INDEX emails_msgid_idx ON emails(message_id_header) WHERE message_id_header IS NOT NULL;
CREATE INDEX emails_thread_idx ON emails(thread_canonical_id);
CREATE INDEX emails_date_idx ON emails(date_sent);
CREATE INDEX emails_from_idx ON emails(from_handle);
CREATE INDEX emails_subject_trgm_idx ON emails USING GIN (subject gin_trgm_ops);
CREATE INDEX emails_body_tsv_idx ON emails USING GIN (body_text_tsv);
CREATE INDEX emails_doc_idx ON emails(document_id);

-- One row per recipient lets us index/query by recipient cleanly.
CREATE TABLE email_recipients (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id        uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  field           text NOT NULL CHECK (field IN ('to', 'cc', 'bcc', 'resent_to', 'resent_cc')),
  position        int NOT NULL,
  handle          text NOT NULL,
  display_name    text
);

CREATE INDEX email_recip_email_idx ON email_recipients(email_id);
CREATE INDEX email_recip_handle_idx ON email_recipients(handle);

-- ----------------------------------------------------------------------------
-- chats: a conversation container for the unified messages table.  Spans
-- iMessage threads, Messenger threads, AI conversations, etc.  Group vs.
-- 1-to-1 distinction tracked here.
-- ----------------------------------------------------------------------------

CREATE TABLE chats (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  platform                 text NOT NULL CHECK (platform IN (
                             'imessage', 'sms_thread', 'messenger', 'google_chat',
                             'chatgpt', 'claude', 'grok', 'voicemail_thread',
                             'voice_call', 'other'
                           )),
  kind                     text NOT NULL CHECK (kind IN ('one_to_one', 'group', 'broadcast')),
  external_thread_id       text,                                       -- platform's id
  display_name             text,
  ai_chat_context_id       uuid,                                       -- FK below
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  pii_tier                 text NOT NULL DEFAULT 'internal'
                             CHECK (pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  created_at_external      timestamptz,                                -- when created on the platform
  ingested_at              timestamptz NOT NULL DEFAULT now(),
  notes                    text
);

CREATE INDEX chats_platform_idx ON chats(platform);
CREATE INDEX chats_external_idx ON chats(platform, external_thread_id);

CREATE TABLE chat_members (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  chat_id             uuid NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  handle              text NOT NULL,
  display_name        text,
  party_id            uuid REFERENCES parties(id),
  joined_at           timestamptz,
  left_at             timestamptz,
  role_in_chat        text                                           -- 'admin' | 'member' | 'self'
);

CREATE INDEX chat_members_chat_idx ON chat_members(chat_id);
CREATE INDEX chat_members_party_idx ON chat_members(party_id) WHERE party_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- messages: unified table for sms/imessage/messenger/ai_chat/voicemail/etc.
-- Anything that's NOT email.  Tree-structured via parent_message_id (for
-- ChatGPT branching, replies, forwarded-as-attachment).
-- ----------------------------------------------------------------------------

CREATE TABLE messages (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  chat_id                  uuid REFERENCES chats(id),
  kind                     text NOT NULL CHECK (kind IN (
                             'sms', 'imessage', 'messenger', 'google_chat',
                             'ai_chat', 'voicemail', 'system', 'other'
                           )),
  external_guid            text,                                     -- platform's stable id
  parent_message_id        uuid REFERENCES messages(id) DEFERRABLE INITIALLY DEFERRED,
  is_current_path          boolean NOT NULL DEFAULT true,            -- for branching trees
  sender_handle            text,
  sender_party_id          uuid REFERENCES parties(id),
  recipient_handles        text[] NOT NULL DEFAULT '{}',
  is_from_me               boolean,
  service                  text,                                     -- 'iMessage' | 'SMS' (per row, redundant with kind)
  sent_at                  timestamptz,
  received_at              timestamptz,
  read_at                  timestamptz,
  body_text                text,
  body_attributed_raw      bytea,                                    -- iOS attributedBody
  expressive_style         text,                                     -- 'slam' | 'invisible_ink' | etc.
  has_attachments          boolean NOT NULL DEFAULT false,
  edit_history             jsonb NOT NULL DEFAULT '[]',              -- [{edited_at, prior_text}, ...]
  unsent_at                timestamptz,
  recording_id             uuid,                                     -- FK added in 50_recordings (voicemail)
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  encoding_repaired        boolean NOT NULL DEFAULT false,           -- true if mojibake fixed
  body_text_tsv            tsvector GENERATED ALWAYS AS (
                             to_tsvector('english', coalesce(body_text, ''))
                           ) STORED,
  pii_tier                 text NOT NULL DEFAULT 'internal'
                             CHECK (pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  ingested_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX messages_matter_idx ON messages(matter_id);
CREATE INDEX messages_chat_idx ON messages(chat_id, sent_at);
CREATE INDEX messages_kind_idx ON messages(kind);
CREATE INDEX messages_guid_idx ON messages(external_guid) WHERE external_guid IS NOT NULL;
CREATE INDEX messages_parent_idx ON messages(parent_message_id) WHERE parent_message_id IS NOT NULL;
CREATE INDEX messages_sender_idx ON messages(sender_handle);
CREATE INDEX messages_sender_party_idx ON messages(sender_party_id) WHERE sender_party_id IS NOT NULL;
CREATE INDEX messages_sent_at_idx ON messages(sent_at);
CREATE INDEX messages_body_tsv_idx ON messages USING GIN (body_text_tsv);

-- Now wire up the deferred FKs from 30_documents.sql

ALTER TABLE attachment_relations
  ADD CONSTRAINT attachment_message_email_fk
  CHECK (
    (message_kind = 'email' AND message_id IS NOT NULL) OR
    (message_kind = 'message' AND message_id IS NOT NULL)
  );
-- Note: we cannot add a polymorphic FK; integrity enforced at app level
-- and via the triggers below.

CREATE OR REPLACE FUNCTION attachment_relations_validate_fk() RETURNS trigger AS $$
BEGIN
  IF NEW.message_kind = 'email' THEN
    PERFORM 1 FROM emails WHERE id = NEW.message_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'attachment_relations.message_id % not in emails', NEW.message_id;
    END IF;
  ELSIF NEW.message_kind = 'message' THEN
    PERFORM 1 FROM messages WHERE id = NEW.message_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'attachment_relations.message_id % not in messages', NEW.message_id;
    END IF;
  ELSE
    RAISE EXCEPTION 'attachment_relations.message_kind must be email or message';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER attachment_relations_validate
  BEFORE INSERT OR UPDATE OF message_id, message_kind ON attachment_relations
  FOR EACH ROW EXECUTE FUNCTION attachment_relations_validate_fk();

-- chunks.message_id can reference either emails or messages (polymorphic).
-- Same trigger pattern.  We add a discriminator column.

ALTER TABLE chunks ADD COLUMN message_kind text
  CHECK (message_kind IS NULL OR message_kind IN ('email', 'message'));

CREATE OR REPLACE FUNCTION chunks_validate_message_fk() RETURNS trigger AS $$
BEGIN
  IF NEW.message_id IS NULL THEN RETURN NEW; END IF;
  IF NEW.message_kind = 'email' THEN
    PERFORM 1 FROM emails WHERE id = NEW.message_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'chunks.message_id % not in emails', NEW.message_id;
    END IF;
  ELSIF NEW.message_kind = 'message' THEN
    PERFORM 1 FROM messages WHERE id = NEW.message_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'chunks.message_id % not in messages', NEW.message_id;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER chunks_validate_message
  BEFORE INSERT OR UPDATE OF message_id, message_kind ON chunks
  FOR EACH ROW EXECUTE FUNCTION chunks_validate_message_fk();

-- ----------------------------------------------------------------------------
-- message_associations: replies, reactions (tapbacks), edits-tracking.
-- A reply child is a regular message with parent_message_id; tapbacks are
-- *associations*, not standalone messages.
-- ----------------------------------------------------------------------------

CREATE TABLE message_associations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  child_message_id uuid REFERENCES messages(id),  -- nullable for pure metadata-only events
  kind            text NOT NULL CHECK (kind IN (
                    'reply', 'tapback_added', 'tapback_removed',
                    'reaction', 'forward', 'pin', 'unpin', 'system_event'
                  )),
  detail          text,                              -- e.g., 'love' | 'thumbs_up' | '🎉'
  actor_handle    text,                              -- who reacted/replied
  active          boolean NOT NULL DEFAULT true,     -- false when removed (audit kept)
  occurred_at     timestamptz,
  source_acquisition_id uuid REFERENCES acquisitions(id),
  notes           text
);

CREATE INDEX msg_assoc_parent_idx ON message_associations(parent_message_id);
CREATE INDEX msg_assoc_child_idx ON message_associations(child_message_id) WHERE child_message_id IS NOT NULL;
CREATE INDEX msg_assoc_kind_idx ON message_associations(kind);

-- ----------------------------------------------------------------------------
-- ai_chat_contexts: Custom GPTs, Claude Projects, Grok personas.
-- ----------------------------------------------------------------------------

CREATE TABLE ai_chat_contexts (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  context_kind             text NOT NULL CHECK (context_kind IN (
                             'custom_gpt', 'claude_project', 'grok_persona', 'user_memory'
                           )),
  external_id              text,
  context_name             text,
  system_prompt            text,
  custom_instructions      text,
  knowledge_files          jsonb NOT NULL DEFAULT '[]',
  created_at_external      timestamptz,
  ingested_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ai_contexts_external_idx ON ai_chat_contexts(context_kind, external_id);

ALTER TABLE chats
  ADD CONSTRAINT chats_ai_context_fk
  FOREIGN KEY (ai_chat_context_id) REFERENCES ai_chat_contexts(id);

-- ----------------------------------------------------------------------------
-- ai_chat_metadata: per-message AI specifics (model, system prompt, tool
-- calls, claimed citations).  Sidecar so the messages table stays uniform.
-- ----------------------------------------------------------------------------

CREATE TABLE ai_chat_metadata (
  message_id              uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  model                   text,
  model_version           text,
  system_prompt           text,
  custom_instructions     text,
  memory_referenced       text[],
  tool_calls              jsonb NOT NULL DEFAULT '[]',
  tool_results            jsonb NOT NULL DEFAULT '[]',
  citations_claimed       jsonb NOT NULL DEFAULT '[]',
  finish_reason           text,
  shared_publicly         boolean NOT NULL DEFAULT false,
  share_url               text,
  shared_at               timestamptz
);

-- ----------------------------------------------------------------------------
-- call_events: phone calls, FaceTime, Messenger calls, voicemail call attempts.
-- ----------------------------------------------------------------------------

CREATE TABLE call_events (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid REFERENCES matters(id),
  message_id          uuid REFERENCES messages(id),                 -- nullable
  platform            text NOT NULL CHECK (platform IN (
                        'phone', 'facetime_audio', 'facetime_video',
                        'messenger', 'whatsapp', 'voip_other'
                      )),
  caller_handle       text,
  called_handle       text,
  caller_party_id     uuid REFERENCES parties(id),
  called_party_id     uuid REFERENCES parties(id),
  initiated_at        timestamptz,
  answered_at         timestamptz,
  ended_at            timestamptz,
  duration_s          int,
  outcome             text CHECK (outcome IN (
                        'connected', 'missed', 'declined', 'voicemail',
                        'failed', 'busy', 'no_answer'
                      )),
  recording_id        uuid,                                          -- FK added in 50_recordings
  jurisdictions_recorded_in text[],                                  -- for consent posture
  consent_basis       text,                                          -- 'one_party_wi' | 'all_party_consent' | etc.
  source_acquisition_id uuid REFERENCES acquisitions(id),
  notes               text
);

CREATE INDEX call_events_initiated_idx ON call_events(initiated_at);
CREATE INDEX call_events_caller_idx ON call_events(caller_handle);
CREATE INDEX call_events_called_idx ON call_events(called_handle);

-- ----------------------------------------------------------------------------
-- voicemail_metadata: carrier-side metadata only voicemail has.
-- ----------------------------------------------------------------------------

CREATE TABLE voicemail_metadata (
  message_id              uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  remote_uid              text,                                     -- carrier's stable id
  callback_number         text,
  carrier                 text,
  expires_at              timestamptz,
  trashed_at_in_source    timestamptz,
  flags_raw               bytea,
  carrier_transcript      text,                                     -- if carrier provided
  is_likely_spam          boolean NOT NULL DEFAULT false,
  seen_in_sources         text[] NOT NULL DEFAULT '{}'              -- which acquisitions saw this VM
);
