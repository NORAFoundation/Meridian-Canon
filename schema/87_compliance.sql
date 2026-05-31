-- schema/87_compliance.sql
-- Mandate-Compliance Engine schema
-- Auditing agency duties, evidence, and compliance.

CREATE TABLE mandates (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  source_type              text NOT NULL CHECK (source_type IN (
                             'statute', 'regulation', 'dcf_standard',
                             'court_order', 'permanency_plan', 'constitutional',
                             'evidence_rule', 'funding_requirement'
                           )),
  source_citation          text NOT NULL,
  exact_text               text,
  required_actor_id        uuid REFERENCES parties(id),
  required_action          text NOT NULL,
  deadline_trigger         text,
  prohibited_action        text,
  required_documentation   text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE compliance_audit (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mandate_id               uuid NOT NULL REFERENCES mandates(id),
  actor_id                 uuid REFERENCES parties(id),
  actual_action            text,
  action_date              timestamptz,
  evidence_document_id     uuid REFERENCES documents(id),
  determination            text NOT NULL CHECK (determination IN (
                             'complied', 'partially_complied', 'failed',
                             'created_barrier', 'maintained_barrier',
                             'relied_on_contested_fact', 'no_evidence',
                             'insufficient_record'
                           )),
  mental_state             text CHECK (mental_state IN (
                             'mistake', 'negligence', 'reckless_disregard',
                             'knowing_violation', 'deliberate_obstruction',
                             'retaliatory', 'not_provable'
                           )),
  proof_of_intent          text,
  harm_caused              text,
  remedy_requested         text,
  notes                    text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE compliance_barriers (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  barrier_type             text NOT NULL,
  created_by_party_id      uuid REFERENCES parties(id),
  affected_party_id        uuid REFERENCES parties(id),
  evidence_document_id     uuid REFERENCES documents(id),
  was_known_to_agency      boolean DEFAULT false,
  agency_notice_date       timestamptz,
  agency_cure_action       text,
  agency_cure_date         timestamptz,
  is_active                boolean DEFAULT true,
  notes                    text
);

CREATE TABLE pat_performance (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mandate_id               uuid NOT NULL REFERENCES mandates(id),
  status                   text NOT NULL CHECK (status IN (
                             'did_it', 'partially_did_it', 'tried',
                             'could_not_do_it', 'prevented', 'did_not_do',
                             'disputed', 'unclear', 'shifted', 'evidence_missing'
                           )),
  attempt_description      text,
  barrier_id               uuid REFERENCES compliance_barriers(id),
  evidence_document_id     uuid REFERENCES documents(id),
  good_cause_argument      text,
  created_at               timestamptz NOT NULL DEFAULT now()
);

-- AUDIT-FIX (HIGH-2): the compliance engine tables held no RLS — any
-- authenticated actor (paralegal, expert, family) could read the full
-- mandate/audit/barrier strategy. These tables encode litigation theory
-- and are owner/counsel only, consistent with privilege_assertions in
-- 99_rls.sql. Default-deny for every other role (no positive policy).
-- Writes restricted to owner/counsel/system.
ALTER TABLE mandates             ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_audit     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_barriers  ENABLE ROW LEVEL SECURITY;
ALTER TABLE pat_performance      ENABLE ROW LEVEL SECURITY;

CREATE POLICY mandates_role ON mandates FOR SELECT
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel'));
CREATE POLICY mandates_modify ON mandates FOR ALL
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'))
  WITH CHECK ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'));

CREATE POLICY compliance_audit_role ON compliance_audit FOR SELECT
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel'));
CREATE POLICY compliance_audit_modify ON compliance_audit FOR ALL
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'))
  WITH CHECK ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'));

CREATE POLICY compliance_barriers_role ON compliance_barriers FOR SELECT
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel'));
CREATE POLICY compliance_barriers_modify ON compliance_barriers FOR ALL
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'))
  WITH CHECK ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'));

CREATE POLICY pat_performance_role ON pat_performance FOR SELECT
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel'));
CREATE POLICY pat_performance_modify ON pat_performance FOR ALL
  USING ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'))
  WITH CHECK ((SELECT current_actor_role()) IN ('owner', 'counsel', 'system'));

-- AUDIT-FIX (MED-8): index the foreign-key columns. Unindexed FKs force
-- sequential scans on join/lookup and on parent-row deletes.
CREATE INDEX compliance_audit_mandate_idx    ON compliance_audit(mandate_id);
CREATE INDEX compliance_barriers_matter_idx  ON compliance_barriers(matter_id);
CREATE INDEX pat_performance_mandate_idx     ON pat_performance(mandate_id);
