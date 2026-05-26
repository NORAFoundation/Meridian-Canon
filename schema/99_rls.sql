-- ============================================================================
-- 99_rls.sql
-- Row-level security.
--
-- Model:
--   - Application sets `app.current_actor_id` per connection (or per txn).
--   - current_actor_role() returns 'owner' | 'counsel' | 'paralegal' |
--     'expert' | 'family' | 'opposing_counsel' | 'court_clerk' | 'system'.
--   - current_actor_pii_ceiling() returns the PII tier the actor may see.
--   - Owner sees everything in their matter.
--   - Counsel sees everything except sources flagged with stricter
--     access_role_floor.
--   - Paralegal/expert/family see scoped subsets per acl_grants.
--   - Opposing counsel sees ONLY production-scoped data — and that data
--     should live in a separate review portal/database in practice.
--     The policies below treat them as essentially excluded from the
--     primary tables; the portal queries the productions schema.
--
-- Audit log is special: hash-chained, append-only, no UPDATE/DELETE.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Helper: does the current actor have any access to a resource?
-- Combines role-default with ACL grants.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION actor_has_grant(
  p_resource_type text, p_resource_id uuid, p_permission text DEFAULT 'read'
) RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM acl_grants
    WHERE actor_id = current_actor_id()
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id
      AND p_permission = ANY(permissions)
      AND (expires_at IS NULL OR expires_at > now())
  )
$$ LANGUAGE sql STABLE;

-- ----------------------------------------------------------------------------
-- Audit log: append-only.  Revoke UPDATE/DELETE; SELECT visibility is
-- limited to owner/counsel.
-- ----------------------------------------------------------------------------

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_log_select ON audit_log FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));

CREATE POLICY audit_log_insert ON audit_log FOR INSERT
  WITH CHECK (true);   -- inserts are mediated by the audit() helper

REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

-- ----------------------------------------------------------------------------
-- Documents and chunks: PII tier ceiling + role check + per-document grants.
-- ----------------------------------------------------------------------------

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_owner_counsel ON documents FOR SELECT
  USING (
    current_actor_role() IN ('owner', 'counsel')
    AND pii_tier_rank(evidentiary_pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
  );

CREATE POLICY documents_paralegal ON documents FOR SELECT
  USING (
    current_actor_role() = 'paralegal'
    AND pii_tier_rank(evidentiary_pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
    AND NOT EXISTS (
      SELECT 1 FROM privilege_assertions pa
      WHERE pa.resource_type = 'document' AND pa.resource_id = documents.id
        AND NOT pa.waived
        AND pa.privilege_type IN ('work_product', 'expert_consulting', 'attorney_client')
    )
  );

CREATE POLICY documents_grant ON documents FOR SELECT
  USING (actor_has_grant('document', id, 'read'));

CREATE POLICY documents_owner_modify ON documents FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

ALTER TABLE chunks ENABLE ROW LEVEL SECURITY;

CREATE POLICY chunks_inherit_doc ON chunks FOR SELECT
  USING (
    pii_tier_rank(pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
    AND EXISTS (
      SELECT 1 FROM documents d
      WHERE d.id = chunks.document_id
        -- documents RLS will further filter
    )
    AND NOT EXISTS (
      SELECT 1 FROM privilege_assertions pa
      WHERE pa.resource_type = 'chunk' AND pa.resource_id = chunks.id
        AND NOT pa.waived
        AND current_actor_role() NOT IN ('owner', 'counsel')
    )
  );

CREATE POLICY chunks_owner_modify ON chunks FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- ----------------------------------------------------------------------------
-- Communications: emails, messages, recordings.
-- AI chats default to counsel-floor — paralegal cannot see unless granted.
-- ----------------------------------------------------------------------------

ALTER TABLE emails ENABLE ROW LEVEL SECURITY;

CREATE POLICY emails_role_pii ON emails FOR SELECT
  USING (
    current_actor_role() IN ('owner', 'counsel', 'paralegal')
    AND pii_tier_rank(pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
  );

CREATE POLICY emails_grant ON emails FOR SELECT
  USING (actor_has_grant('email', id, 'read'));

CREATE POLICY emails_owner_modify ON emails FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY messages_role_pii ON messages FOR SELECT
  USING (
    pii_tier_rank(pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
    AND (
      current_actor_role() IN ('owner', 'counsel')
      OR (current_actor_role() = 'paralegal' AND kind != 'ai_chat')
      OR (current_actor_role() = 'expert' AND actor_has_grant('message', id, 'read'))
      OR (current_actor_role() = 'family' AND actor_has_grant('message', id, 'read'))
    )
  );

CREATE POLICY messages_owner_modify ON messages FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

ALTER TABLE recordings ENABLE ROW LEVEL SECURITY;

CREATE POLICY recordings_role_pii ON recordings FOR SELECT
  USING (
    pii_tier_rank(pii_tier) <= pii_tier_rank(current_actor_pii_ceiling())
    AND (
      current_actor_role() IN ('owner', 'counsel', 'paralegal')
      OR actor_has_grant('recording', id, 'read')
    )
  );

CREATE POLICY recordings_owner_modify ON recordings FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- ----------------------------------------------------------------------------
-- Telemetry: highest tier by default — owner + counsel only, with
-- explicit grants required for anyone else.
-- ----------------------------------------------------------------------------

ALTER TABLE device_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE location_pings ENABLE ROW LEVEL SECURITY;
ALTER TABLE health_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE workout_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE wifi_associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE bluetooth_encounters ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_sign_ins ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE social_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tracking_disclosures ENABLE ROW LEVEL SECURITY;

CREATE POLICY telemetry_owner_counsel_de ON device_events FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_lp ON location_pings FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_hr ON health_records FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_wr ON workout_routes FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_wa ON wifi_associations FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_bt ON bluetooth_encounters FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_si ON account_sign_ins FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_bh ON browser_history FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_n  ON notes FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel')
         AND pii_tier_rank(pii_tier) <= pii_tier_rank(current_actor_pii_ceiling()));
CREATE POLICY telemetry_owner_counsel_sp ON social_posts FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY telemetry_owner_counsel_ae ON activity_events FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY telemetry_owner_counsel_td ON tracking_disclosures FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));

-- Modify policies (owner/counsel/system only)
DO $$ DECLARE t text; BEGIN
  FOR t IN SELECT unnest(ARRAY[
    'device_events','location_pings','health_records','workout_routes',
    'wifi_associations','bluetooth_encounters','account_sign_ins',
    'browser_history','notes','social_posts','activity_events',
    'tracking_disclosures'
  ]) LOOP
    EXECUTE format(
      'CREATE POLICY %I_modify ON %I FOR ALL '
      'USING (current_actor_role() IN (''owner'',''counsel'',''system'')) '
      'WITH CHECK (current_actor_role() IN (''owner'',''counsel'',''system''))',
      t || '_modify_owner', t
    );
  END LOOP;
END $$;

-- ----------------------------------------------------------------------------
-- Financial + telephony: owner + counsel + paralegal default; CSLI tighter.
-- ----------------------------------------------------------------------------

ALTER TABLE financial_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE p2p_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cdrs ENABLE ROW LEVEL SECURITY;
ALTER TABLE cdr_locations ENABLE ROW LEVEL SECURITY;

CREATE POLICY fa_role ON financial_accounts FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY fa_modify ON financial_accounts FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY tx_role ON transactions FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY tx_modify ON transactions FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY p2p_role ON p2p_transfers FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY p2p_modify ON p2p_transfers FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY cdrs_role ON cdrs FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY cdrs_modify ON cdrs FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- CSLI: owner + counsel only by default (privacy-elevated).
CREATE POLICY cdr_loc_role ON cdr_locations FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY cdr_loc_modify ON cdr_locations FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- ----------------------------------------------------------------------------
-- Privilege + redactions: owner + counsel only for full visibility.
-- Paralegals see redaction *existence* but not the master content
-- (handled at app layer via redacted-version selection, not here).
-- ----------------------------------------------------------------------------

ALTER TABLE privilege_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE redactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE withheld_documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY pa_role ON privilege_assertions FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY pa_modify ON privilege_assertions FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY red_role ON redactions FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY red_modify ON redactions FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY wh_role ON withheld_documents FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel'));
CREATE POLICY wh_modify ON withheld_documents FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- ----------------------------------------------------------------------------
-- Productions: visible per recipient mapping (this DB is the OUTBOUND view;
-- the inbound portal lives elsewhere).  Outbound productions are visible
-- to owner/counsel/paralegal here.
-- ----------------------------------------------------------------------------

ALTER TABLE productions ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_redactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY prod_role ON productions FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY prod_modify ON productions FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY proddocs_role ON production_documents FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY proddocs_modify ON production_documents FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

CREATE POLICY prodred_role ON production_redactions FOR SELECT
  USING (current_actor_role() IN ('owner', 'counsel', 'paralegal'));
CREATE POLICY prodred_modify ON production_redactions FOR ALL
  USING (current_actor_role() IN ('owner', 'counsel', 'system'))
  WITH CHECK (current_actor_role() IN ('owner', 'counsel', 'system'));

-- ----------------------------------------------------------------------------
-- Default deny for opposing_counsel and court_clerk on every primary table.
-- These roles should not be querying the live DB at all — the external
-- review portal queries a separate schema/database.  The lack of any
-- positive policy here means RLS denies by default.  We document with a
-- no-op block.
-- ----------------------------------------------------------------------------

-- (No policies granting opposing_counsel or court_clerk; default-deny.)
