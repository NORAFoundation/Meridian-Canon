-- ============================================================================
-- A0_attestations.sql  (Phase A: Canon foundation)
--
-- Adds the attestations table that stores every Canon-conformant artifact
-- the system emits. References paper §6.10 (attestation kinds), §8 (crypto
-- protocol), §6.2 (procedural substrate, matter scoping).
--
-- Down: schema/A0_attestations.down.sql
-- ============================================================================

CREATE TABLE attestations (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- ULID printed in the artifact's attestation_id field. Stored
  -- separately from id so the artifact's external identity is
  -- not coupled to row insertion order.
  attestation_id           text UNIQUE NOT NULL,
  CHECK (attestation_id ~ '^[A-Z0-9]+$'),

  kind                     text NOT NULL CHECK (kind IN (
                             'observation', 'enrichment', 'search', 'brief', 'audit'
                           )),
  canon_version            text NOT NULL,

  -- Matter scoping (paper §6.2 procedural substrate).
  matter_id                uuid REFERENCES matters(id),

  issued_at                timestamptz NOT NULL,
  issuer                   text NOT NULL,
  subject                  text,

  -- Cryptographic binding fields, denormalized from payload->'seal' for
  -- indexed lookup. The authoritative source remains the payload jsonb.
  chain_hash               text NOT NULL,
  CHECK (chain_hash ~ '^sha256:[0-9a-f]{64}$'),
  signature                text NOT NULL,                          -- base64
  public_key_fingerprint   text NOT NULL,
  CHECK (public_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  public_key_url           text NOT NULL,

  -- Full Canon-conformant artifact. The wire format. RFC 8785 canonicalization
  -- of payload (with seal field excluded) MUST hash to chain_hash.
  payload                  jsonb NOT NULL,

  -- Per-kind extensions (e.g., search query for SearchAttestations).
  kind_specific            jsonb,

  created_at               timestamptz NOT NULL DEFAULT now()
);

-- Indexes by the queries we expect: matter timeline, kind filter, lookup-by-id.
CREATE INDEX attestations_matter_idx     ON attestations(matter_id, issued_at);
CREATE INDEX attestations_kind_idx       ON attestations(kind, issued_at);
CREATE INDEX attestations_fingerprint_idx ON attestations(public_key_fingerprint);

-- Audit-log emission on every Canon write.
CREATE OR REPLACE FUNCTION attestations_audit_trigger() RETURNS trigger AS $$
BEGIN
  PERFORM audit('attestation_emitted', 'attestation', NEW.id,
                jsonb_build_object('kind', NEW.kind, 'attestation_id', NEW.attestation_id));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER attestations_audit
  AFTER INSERT ON attestations
  FOR EACH ROW EXECUTE FUNCTION attestations_audit_trigger();

-- Witness wrapping (Phase B): each acquisition gets at most one
-- ObservationAttestation. The link is bidirectional so verifiers can
-- walk acquisition -> attestation and back.
ALTER TABLE acquisitions
  ADD COLUMN obs_attestation_id text REFERENCES attestations(attestation_id);

CREATE INDEX acquisitions_obs_attestation_idx
  ON acquisitions(obs_attestation_id) WHERE obs_attestation_id IS NOT NULL;
