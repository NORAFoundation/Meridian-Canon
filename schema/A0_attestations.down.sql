-- Reverses A0_attestations.sql.

ALTER TABLE acquisitions DROP COLUMN IF EXISTS obs_attestation_id;
-- AUDIT-FIX (CRIT-4): reverse the append-only / RLS hardening.
DROP POLICY IF EXISTS attestations_insert ON attestations;
DROP POLICY IF EXISTS attestations_select ON attestations;
-- RLS disable is implicit when the table is dropped, but be explicit for
-- partial-rollback safety.
ALTER TABLE attestations DISABLE ROW LEVEL SECURITY;
DROP TRIGGER IF EXISTS attestations_no_mutation ON attestations;
DROP FUNCTION IF EXISTS attestations_deny_mutation();
DROP TRIGGER IF EXISTS attestations_audit ON attestations;
DROP FUNCTION IF EXISTS attestations_audit_trigger();
DROP INDEX IF EXISTS attestations_fingerprint_idx;
DROP INDEX IF EXISTS attestations_kind_idx;
DROP INDEX IF EXISTS attestations_matter_idx;
DROP TABLE IF EXISTS attestations;
