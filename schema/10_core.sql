-- ============================================================================
-- 10_core.sql
-- Matters, parties, actors, RBAC primitives, audit log.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- matters: top-level partition for everything.  In a single-matter deployment
-- there's just one row, but the schema supports parallel matters that share
-- the same database (e.g., circuit-court case + administrative proceeding).
-- ----------------------------------------------------------------------------

CREATE TABLE matters (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  short_name      text NOT NULL UNIQUE,        -- 'example-matter-2026'
  caption         text,                        -- "In re Doe, et al."
  forum           text,                        -- 'Example County Circuit Court'
  case_numbers    text[] DEFAULT '{}',         -- can span courts; primary at index 0
  opened_at       timestamptz NOT NULL DEFAULT now(),
  closed_at       timestamptz,
  description     text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- parties: people, organizations, agencies, opposing firms, courts.
-- Distinct from "actors" — a party is a real-world entity in the case;
-- an actor is a login that operates the system.  Many parties have no
-- corresponding actor (e.g., DHS, opposing party not given portal access).
-- ----------------------------------------------------------------------------

CREATE TABLE parties (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id       uuid REFERENCES matters(id),
  kind            text NOT NULL CHECK (kind IN (
                    'individual', 'organization', 'court', 'government_agency',
                    'law_firm', 'synthetic'    -- synthetic = AI assistant
                  )),
  display_name    text NOT NULL,
  legal_name      text,
  role_in_matter  text CHECK (role_in_matter IS NULL OR role_in_matter IN (
                    'self', 'co_plaintiff', 'co_defendant', 'opposing_party',
                    'witness', 'third_party', 'counsel', 'opposing_counsel',
                    'expert', 'court', 'agency', 'family', 'media', 'other'
                  )),
  metadata        jsonb NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX parties_matter_idx ON parties(matter_id);
CREATE INDEX parties_kind_idx ON parties(kind);

-- Handles let us link emails, phone numbers, account ids, social handles
-- back to a canonical party.  An email like alice@example.com may show up
-- across email, FB Messenger, LinkedIn — same handle string, same party.

CREATE TABLE party_handles (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id        uuid NOT NULL REFERENCES parties(id) ON DELETE CASCADE,
  handle_kind     text NOT NULL CHECK (handle_kind IN (
                    'email', 'phone', 'apple_id', 'google_account', 'meta_account',
                    'username', 'screen_name', 'wallet_address', 'other'
                  )),
  handle          text NOT NULL,
  display_name    text,
  verified        boolean NOT NULL DEFAULT false,
  first_seen_at   timestamptz,
  last_seen_at    timestamptz,
  source_notes    text,
  UNIQUE (handle_kind, handle, party_id)
);

CREATE INDEX party_handles_handle_idx ON party_handles(handle_kind, handle);

-- ----------------------------------------------------------------------------
-- actors: anyone who can log into the system.  Owner, counsel, expert,
-- paralegal, family, opposing counsel (portal-only), system service accounts.
-- ----------------------------------------------------------------------------

CREATE TABLE actors (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id        uuid REFERENCES parties(id),    -- nullable; system accounts have none
  display_name    text NOT NULL,
  email           text,
  role            text NOT NULL CHECK (role IN (
                    'owner', 'counsel', 'paralegal', 'expert',
                    'family', 'opposing_counsel', 'court_clerk', 'system'
                  )),
  pii_ceiling     text NOT NULL DEFAULT 'low' CHECK (pii_ceiling IN (
                    'public', 'low', 'internal', 'sensitive', 'privileged', 'work_product'
                  )),
  is_active       boolean NOT NULL DEFAULT true,
  mfa_required    boolean NOT NULL DEFAULT true,
  notes           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  deactivated_at  timestamptz
);

CREATE INDEX actors_role_idx ON actors(role) WHERE is_active;
CREATE INDEX actors_party_idx ON actors(party_id);

-- Now we can define current_actor_role(), which RLS leans on heavily.

CREATE OR REPLACE FUNCTION current_actor_role() RETURNS text AS $$
  SELECT role FROM actors WHERE id = current_actor_id() AND is_active
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_actor_pii_ceiling() RETURNS text AS $$
  SELECT pii_ceiling FROM actors WHERE id = current_actor_id() AND is_active
$$ LANGUAGE sql STABLE;

-- PII tier ordering for RLS comparisons.  Lower number = lower sensitivity.
CREATE OR REPLACE FUNCTION pii_tier_rank(tier text) RETURNS int AS $$
  SELECT CASE tier
    WHEN 'public'       THEN 0
    WHEN 'low'          THEN 1
    WHEN 'internal'     THEN 2
    WHEN 'sensitive'    THEN 3
    WHEN 'privileged'   THEN 4
    WHEN 'work_product' THEN 5
    ELSE NULL
  END
$$ LANGUAGE sql IMMUTABLE;

-- ----------------------------------------------------------------------------
-- counsel_relationships: when an attorney engaged.  Privilege turns ON for
-- communications shared with this counsel after engaged_at.
-- ----------------------------------------------------------------------------

CREATE TABLE counsel_relationships (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid NOT NULL REFERENCES matters(id),
  client_party_id          uuid NOT NULL REFERENCES parties(id),
  counsel_party_id         uuid NOT NULL REFERENCES parties(id),
  scope                    text NOT NULL CHECK (scope IN ('full', 'limited', 'consulting')),
  scope_description        text,
  engaged_at               timestamptz NOT NULL,
  ended_at                 timestamptz,
  signed_engagement_doc_id uuid,                 -- FK added later (forward ref to documents)
  notes                    text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX counsel_rel_client_idx ON counsel_relationships(client_party_id);

-- ----------------------------------------------------------------------------
-- expert_relationships: testifying vs. consulting matters for privilege rules.
-- ----------------------------------------------------------------------------

CREATE TABLE expert_relationships (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid NOT NULL REFERENCES matters(id),
  expert_party_id     uuid NOT NULL REFERENCES parties(id),
  expert_type         text NOT NULL CHECK (expert_type IN (
                        'consulting', 'testifying', 'rebuttal'
                      )),
  retained_at         timestamptz NOT NULL,
  ended_at            timestamptz,
  retained_through_counsel_id uuid REFERENCES counsel_relationships(id),
  scope_description   text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- acl_grants: object-scoped grants beyond the role default.
-- E.g., "share this folder/document with my brother", "give expert X access
-- to recordings tagged Y".  Resource is a (table, id) pair; permissions is
-- an array of verbs.
-- ----------------------------------------------------------------------------

CREATE TABLE acl_grants (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id        uuid NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
  resource_type   text NOT NULL,    -- 'document' | 'recording' | 'message' | 'tag' | 'folder'
  resource_id     uuid NOT NULL,
  permissions     text[] NOT NULL CHECK (cardinality(permissions) > 0),
                  -- 'read' | 'annotate' | 'redact' | 'tag' | 'export' | 'produce'
  granted_by      uuid REFERENCES actors(id),
  granted_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  reason          text
);

CREATE INDEX acl_grants_lookup_idx ON acl_grants(actor_id, resource_type, resource_id);
CREATE INDEX acl_grants_resource_idx ON acl_grants(resource_type, resource_id);

-- ----------------------------------------------------------------------------
-- audit_log: hash-chained, append-only.  Every read of sensitive data, every
-- write, every export, every authentication.  The hash chain makes tampering
-- detectable; revoke UPDATE/DELETE in 99_rls.sql.
-- ----------------------------------------------------------------------------

CREATE TABLE audit_log (
  id              bigserial PRIMARY KEY,
  occurred_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_id        uuid REFERENCES actors(id),
  matter_id       uuid REFERENCES matters(id),
  action          text NOT NULL,                -- 'read' | 'write' | 'export' | 'login' | etc.
  resource_type   text,
  resource_id     uuid,
  payload         jsonb NOT NULL DEFAULT '{}',
  ip_address      inet,
  user_agent      text,
  prev_hash       text,
  hash            text NOT NULL
);

CREATE INDEX audit_log_actor_idx ON audit_log(actor_id, occurred_at);
CREATE INDEX audit_log_resource_idx ON audit_log(resource_type, resource_id, occurred_at);
CREATE INDEX audit_log_action_idx ON audit_log(action, occurred_at);

-- Hash-chain trigger: each row's hash includes the prior row's hash.
-- Note: under high write contention, advisory locks would be needed to
-- guarantee strict linear chain.  At this scale (single user + workers),
-- a SERIALIZABLE transaction or a row-level lock on the prior tail row
-- is sufficient.  See companion app code.

CREATE OR REPLACE FUNCTION audit_log_hash_trigger() RETURNS trigger AS $$
DECLARE
  prev text;
BEGIN
  -- AUDIT-FIX (CRIT-1): lock the current chain tail (FOR UPDATE) so two
  -- concurrent inserts cannot read the same prev_hash and fork the chain.
  -- The row lock serializes chain extension: the second inserter blocks
  -- until the first commits, then reads the new tail. Hash composition is
  -- unchanged.
  SELECT hash INTO prev FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE;
  NEW.prev_hash := prev;
  NEW.hash := sha256_hex(
    coalesce(prev, '') || '|' ||
    NEW.occurred_at::text || '|' ||
    coalesce(NEW.actor_id::text, '') || '|' ||
    coalesce(NEW.matter_id::text, '') || '|' ||
    NEW.action || '|' ||
    coalesce(NEW.resource_type, '') || '|' ||
    coalesce(NEW.resource_id::text, '') || '|' ||
    coalesce(NEW.payload::text, '{}')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_hash
  BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_hash_trigger();

-- Convenience: emit an audit row.  Apps call this; the trigger handles hashing.
CREATE OR REPLACE FUNCTION audit(
  p_action text, p_resource_type text DEFAULT NULL, p_resource_id uuid DEFAULT NULL,
  p_payload jsonb DEFAULT '{}'
) RETURNS bigint AS $$
DECLARE new_id bigint;
BEGIN
  INSERT INTO audit_log (actor_id, action, resource_type, resource_id, payload)
  VALUES (current_actor_id(), p_action, p_resource_type, p_resource_id, p_payload)
  RETURNING id INTO new_id;
  RETURN new_id;
END;
$$ LANGUAGE plpgsql;
