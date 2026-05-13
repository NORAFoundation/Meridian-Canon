-- ============================================================================
-- 70_financial_telephony.sql
-- Financial accounts, statements, transactions, P2P transfers.
-- Subscriber lines, CDRs, optional CSLI locations.
-- ============================================================================

CREATE TABLE financial_accounts (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id                uuid REFERENCES matters(id),
  owner_party_id           uuid REFERENCES parties(id),
  institution              text NOT NULL,                             -- 'Royal Credit Union', 'Wells Fargo', etc.
  account_type             text NOT NULL CHECK (account_type IN (
                             'checking', 'savings', 'credit_card',
                             'investment', 'mortgage', 'auto_loan',
                             'venmo', 'zelle', 'cashapp', 'paypal',
                             'apple_card', 'apple_cash', 'google_pay',
                             'crypto_wallet', 'other'
                           )),
  account_number_last4     text,                                      -- last 4 only; never full PAN
  account_label            text,
  currency                 text NOT NULL DEFAULT 'USD',
  opened_at                date,
  closed_at                date,
  pii_tier                 text NOT NULL DEFAULT 'sensitive'
                             CHECK (pii_tier IN (
                               'public', 'low', 'internal', 'sensitive',
                               'privileged', 'work_product'
                             )),
  notes                    text
);

CREATE INDEX fin_accounts_owner_idx ON financial_accounts(owner_party_id);
CREATE INDEX fin_accounts_inst_idx ON financial_accounts(institution);

-- Joint accounts: many parties to one account.
CREATE TABLE financial_account_owners (
  account_id        uuid NOT NULL REFERENCES financial_accounts(id) ON DELETE CASCADE,
  party_id          uuid NOT NULL REFERENCES parties(id),
  ownership_kind    text CHECK (ownership_kind IN (
                      'sole', 'joint', 'authorized_user', 'beneficiary', 'trustee'
                    )),
  PRIMARY KEY (account_id, party_id)
);

CREATE TABLE financial_statements (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id               uuid NOT NULL REFERENCES financial_accounts(id),
  statement_document_id    uuid NOT NULL REFERENCES documents(id),
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  period_start             date NOT NULL,
  period_end               date NOT NULL,
  beginning_balance_minor  bigint,
  ending_balance_minor     bigint,
  imported_at              timestamptz NOT NULL DEFAULT now(),
  parser_version           text
);

CREATE INDEX fin_statements_account_idx ON financial_statements(account_id, period_start);

CREATE TABLE transactions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id               uuid NOT NULL REFERENCES financial_accounts(id),
  statement_id             uuid REFERENCES financial_statements(id),
  posted_at                timestamptz,
  transaction_at           timestamptz,                                -- when the merchant captured it
  amount_minor             bigint NOT NULL,
  currency                 text NOT NULL DEFAULT 'USD',
  direction                text NOT NULL CHECK (direction IN ('debit', 'credit')),
  description              text,
  memo                     text,
  counterparty_name        text,
  counterparty_handle      text,
  category_raw             text,
  external_txn_id          text,                                       -- bank's stable id
  reverses_transaction_id  uuid REFERENCES transactions(id),           -- for refunds
  source_acquisition_id    uuid REFERENCES acquisitions(id),
  parser_version           text,
  description_tsv          tsvector GENERATED ALWAYS AS (
                             to_tsvector('english',
                               coalesce(description, '') || ' ' ||
                               coalesce(memo, '') || ' ' ||
                               coalesce(counterparty_name, ''))
                           ) STORED,
  ingested_at              timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_id, external_txn_id)
);

CREATE INDEX transactions_account_posted_idx ON transactions(account_id, posted_at);
CREATE INDEX transactions_amount_idx ON transactions(amount_minor);
CREATE INDEX transactions_counterparty_idx ON transactions(counterparty_handle);
CREATE INDEX transactions_description_tsv_idx ON transactions USING GIN (description_tsv);

CREATE TABLE p2p_transfers (
  transaction_id          uuid PRIMARY KEY REFERENCES transactions(id) ON DELETE CASCADE,
  platform                text NOT NULL CHECK (platform IN (
                            'venmo', 'zelle', 'cashapp', 'paypal',
                            'apple_cash', 'google_pay', 'wise', 'other'
                          )),
  sender_handle           text,
  recipient_handle        text,
  is_request              boolean NOT NULL DEFAULT false,
  visibility              text CHECK (visibility IS NULL OR visibility IN (
                            'public', 'friends', 'private'
                          )),
  related_message_id      uuid REFERENCES messages(id),
  external_payment_id     text
);

CREATE INDEX p2p_platform_idx ON p2p_transfers(platform);
CREATE INDEX p2p_recipient_idx ON p2p_transfers(recipient_handle);

-- ============================================================================
-- Telephony: subscriber lines, CDRs, optional CSLI.
-- ============================================================================

CREATE TABLE cdr_subscriber_lines (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id            uuid REFERENCES parties(id),
  phone_number        text NOT NULL,
  carrier             text,
  account_label       text,
  imei                text,
  imsi                text,
  active_from         date,
  active_to           date,
  notes               text,
  UNIQUE (phone_number, carrier, active_from)
);

CREATE INDEX cdr_lines_phone_idx ON cdr_subscriber_lines(phone_number);

CREATE TABLE cdrs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subscriber_line_id  uuid NOT NULL REFERENCES cdr_subscriber_lines(id),
  peer_number         text,
  direction           text NOT NULL CHECK (direction IN ('in', 'out')),
  initiated_at        timestamptz NOT NULL,
  answered_at         timestamptz,
  duration_s          int,
  type                text NOT NULL CHECK (type IN ('voice', 'sms', 'mms', 'data')),
  status              text CHECK (status IS NULL OR status IN (
                        'connected', 'missed', 'voicemail', 'declined',
                        'failed', 'busy', 'no_answer'
                      )),
  route               text,
  external_record_id  text,
  source_acquisition_id uuid REFERENCES acquisitions(id),
  notes               text,
  UNIQUE (subscriber_line_id, external_record_id)
);

CREATE INDEX cdrs_line_time_idx ON cdrs(subscriber_line_id, initiated_at);
CREATE INDEX cdrs_peer_idx ON cdrs(peer_number);
CREATE INDEX cdrs_initiated_idx ON cdrs(initiated_at);

-- CSLI is highly sensitive — separate table with its own RLS.
CREATE TABLE cdr_locations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cdr_id              uuid NOT NULL REFERENCES cdrs(id) ON DELETE CASCADE,
  cell_tower_id       text,
  azimuth_deg         smallint,
  estimated_lat       double precision,
  estimated_lng       double precision,
  estimated_geog      geography(Point, 4326),
  accuracy_radius_m   int,
  observed_at         timestamptz NOT NULL,
  source_acquisition_id uuid REFERENCES acquisitions(id),
  notes               text
);

CREATE INDEX cdr_locations_cdr_idx ON cdr_locations(cdr_id);
CREATE INDEX cdr_locations_geog_idx ON cdr_locations USING GIST (estimated_geog);
CREATE INDEX cdr_locations_observed_idx ON cdr_locations(observed_at);
