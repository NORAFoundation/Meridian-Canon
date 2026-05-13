-- Reverses A0_attestations.sql.

ALTER TABLE acquisitions DROP COLUMN IF EXISTS obs_attestation_id;
DROP TRIGGER IF EXISTS attestations_audit ON attestations;
DROP FUNCTION IF EXISTS attestations_audit_trigger();
DROP INDEX IF EXISTS attestations_fingerprint_idx;
DROP INDEX IF EXISTS attestations_kind_idx;
DROP INDEX IF EXISTS attestations_matter_idx;
DROP TABLE IF EXISTS attestations;
