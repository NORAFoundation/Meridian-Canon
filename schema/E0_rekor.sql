-- Phase 10: Rekor transparency log entries
-- Stores the log metadata returned after publishing a sealed attestation to Rekor.
-- Each row provides an external witness that the attestation existed at integrated_time.

CREATE TABLE IF NOT EXISTS rekor_entries (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id   text NOT NULL,
    log_index        bigint NOT NULL,
    log_id           text NOT NULL,
    entry_uuid       text NOT NULL UNIQUE,
    integrated_time  timestamptz NOT NULL,
    verification_url text NOT NULL,
    rekor_url        text NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rekor_entries_attestation_idx ON rekor_entries(attestation_id);
CREATE INDEX IF NOT EXISTS rekor_entries_integrated_time_idx ON rekor_entries(integrated_time);

COMMENT ON TABLE rekor_entries IS
    'External transparency log entries from Rekor. Each row is a third-party witness '
    'that a Canon Attestation existed with a specific chain_hash at integrated_time. '
    'verification_url is publicly accessible for independent verification.';
