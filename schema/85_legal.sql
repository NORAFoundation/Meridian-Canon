-- ============================================================================
-- 85_legal.sql
-- Privilege assertions, redactions (master copy), withheld documents
-- (privilege log), legal holds.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- privilege_assertions: a privilege is *asserted* on a document or chunk,
-- with a basis and a counsel/expert relationship that triggered it.
-- Privilege filtering at retrieval time joins through this table.
-- ----------------------------------------------------------------------------

CREATE TABLE privilege_assertions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  resource_type            text NOT NULL CHECK (resource_type IN (
                             'document', 'chunk', 'email', 'message',
                             'recording', 'transcript', 'note',
                             'social_post', 'activity_event'
                           )),
  resource_id              uuid NOT NULL,
  privilege_type           text NOT NULL CHECK (privilege_type IN (
                             'attorney_client', 'work_product',
                             'expert_consulting', 'joint_defense',
                             'common_interest', 'clergy', 'spousal',
                             'doctor_patient', 'therapist_patient',
                             'fifth_amendment', 'trade_secret',
                             'hipaa_protected', 'fcra_protected',
                             'fmla_protected', 'student_record_ferpa',
                             'minor_child_welfare', 'other'
                           )),
  basis                    text NOT NULL,                            -- statute / rule / case cite
  asserted_at              timestamptz NOT NULL DEFAULT now(),
  asserted_by_actor        uuid REFERENCES actors(id),
  shared_with_counsel_id   uuid REFERENCES counsel_relationships(id),
  shared_with_expert_id    uuid REFERENCES expert_relationships(id),
  waived                   boolean NOT NULL DEFAULT false,
  waived_at                timestamptz,
  waived_to_party_id       uuid REFERENCES parties(id),
  waiver_basis             text,
  notes                    text
);

CREATE INDEX privilege_resource_idx ON privilege_assertions(resource_type, resource_id);
CREATE INDEX privilege_type_idx ON privilege_assertions(privilege_type);
CREATE INDEX privilege_active_idx ON privilege_assertions(resource_type, resource_id)
  WHERE NOT waived;

-- ----------------------------------------------------------------------------
-- redactions: master-copy redactions on documents.  Distinct from
-- production_redactions which are frozen with each production.  The
-- master may be re-redacted; productions made under prior redactions
-- remain unchanged.
-- ----------------------------------------------------------------------------

CREATE TABLE redactions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id              uuid NOT NULL REFERENCES documents(id),
  page                     int,
  bbox                     jsonb,
  char_range               int4range,
  reason                   text NOT NULL,
  reason_statute_cite      text,
  redacted_text_replacement text,
  applied_by_actor         uuid REFERENCES actors(id),
  applied_at               timestamptz NOT NULL DEFAULT now(),
  reviewed_by_actor        uuid REFERENCES actors(id),
  reviewed_at              timestamptz,
  notes                    text
);

CREATE INDEX redactions_doc_idx ON redactions(document_id);

-- Statutes commonly cited in WI / federal redactions; reference list,
-- not enforced.
CREATE TABLE redaction_grounds_lookup (
  citation            text PRIMARY KEY,
  description         text NOT NULL,
  jurisdiction        text NOT NULL                                  -- 'WI' | 'US' | 'HIPAA'
);

-- ----------------------------------------------------------------------------
-- withheld_documents: per-production list of documents withheld for
-- privilege.  Materializes the privilege log for a given production.
-- ----------------------------------------------------------------------------

CREATE TABLE withheld_documents (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  production_id            uuid NOT NULL REFERENCES productions(id) ON DELETE CASCADE,
  document_id              uuid NOT NULL REFERENCES documents(id),
  privilege_assertion_id   uuid NOT NULL REFERENCES privilege_assertions(id),
  description_for_log      text NOT NULL,                            -- the entry in the privilege log
  date_of_document         date,
  authors                  text[],
  recipients               text[],
  subject                  text,
  notes                    text,
  UNIQUE (production_id, document_id)
);

CREATE INDEX withheld_production_idx ON withheld_documents(production_id);

-- ----------------------------------------------------------------------------
-- legal_holds: a notice that certain data must not be deleted or altered.
-- Often imposed before discovery.  Schema notes it; enforcement is at the
-- application layer (block deletes for held resources).
-- ----------------------------------------------------------------------------

CREATE TABLE legal_holds (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid NOT NULL REFERENCES matters(id),
  hold_name           text NOT NULL,
  scope_description   text NOT NULL,                                 -- "all comms with X from Y to Z"
  scope_query         jsonb,                                         -- structured criteria for automated checks
  imposed_at          date NOT NULL,
  released_at         date,
  imposed_by_actor    uuid REFERENCES actors(id),
  notes               text
);

CREATE INDEX legal_holds_matter_idx ON legal_holds(matter_id) WHERE released_at IS NULL;
