-- ============================================================================
-- 80_telemetry.sql
-- Devices, device events (knowledgeC + macOS unified logs),
-- location pings, place observations, health, workout routes,
-- WiFi/Bluetooth associations, account sign-ins, browser history,
-- notes, social posts, activity events, off-platform tracking.
--
-- Telemetry defaults to elevated PII tier and tight RLS — see 99_rls.sql.
-- ============================================================================

CREATE TABLE devices (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id            uuid REFERENCES parties(id),
  device_type         text NOT NULL CHECK (device_type IN (
                        'iphone', 'ipad', 'mac', 'apple_watch',
                        'android_phone', 'android_tablet', 'pc',
                        'chromebook', 'iot', 'other'
                      )),
  identifier          text,                                          -- UDID, serial
  name                text,
  model               text,
  os_versions_seen    text[] NOT NULL DEFAULT '{}',
  acquired_at         date,
  retired_at          date,
  notes               text
);

CREATE INDEX devices_party_idx ON devices(party_id);
CREATE INDEX devices_identifier_idx ON devices(identifier) WHERE identifier IS NOT NULL;

-- Wire up the deferred FK from 50_recordings.
ALTER TABLE recordings
  ADD CONSTRAINT recordings_device_fk
  FOREIGN KEY (device_id) REFERENCES devices(id);

-- ----------------------------------------------------------------------------
-- device_events: unified stream from knowledgeC.db, macOS unified logs,
-- Android usage stats.  One row per event with start/end (events are often
-- intervals — app in focus from T1 to T2).
-- ----------------------------------------------------------------------------

CREATE TABLE device_events (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  stream              text NOT NULL,
                      -- 'app_focus' | 'app_install' | 'app_usage' |
                      -- 'lock_state' | 'charging' | 'display_backlit' |
                      -- 'bluetooth_connected' | 'audio_playing' |
                      -- 'siri_voice_trigger' | 'wake' | 'sleep' |
                      -- 'wrist_detect' | 'wifi_associated' | 'orientation'
  started_at          timestamptz NOT NULL,
  ended_at            timestamptz,
  payload             jsonb NOT NULL DEFAULT '{}',
  source_acquisition_id uuid REFERENCES acquisitions(id),
  parser_version      text NOT NULL,
  CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX device_events_device_time_idx ON device_events(device_id, started_at);
CREATE INDEX device_events_stream_idx ON device_events(stream, started_at);
CREATE INDEX device_events_payload_idx ON device_events USING GIN (payload);

-- ----------------------------------------------------------------------------
-- location_pings: any positional observation about a subject.  Source
-- vocabulary covers Maps Timeline, Significant Locations, Find My,
-- photo EXIF, CDR CSLI, and manual.  Geography for radius queries.
-- ----------------------------------------------------------------------------

CREATE TABLE location_pings (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_party_id         uuid REFERENCES parties(id),
  device_id                uuid REFERENCES devices(id),
  observed_at              timestamptz NOT NULL,
  lat                      double precision NOT NULL,
  lng                      double precision NOT NULL,
  geog                     geography(Point, 4326) GENERATED ALWAYS AS (
                             ST_SetSRID(ST_MakePoint(lng, lat), 4326)::geography
                           ) STORED,
  altitude_m               numeric,
  speed_mps                numeric,
  heading_deg              numeric,
  accuracy_radius_m        int,
  source_kind              text NOT NULL CHECK (source_kind IN (
                             'maps_timeline', 'significant_locations',
                             'find_my', 'photo_exif', 'cdr_csli',
                             'wifi_geolocation', 'manual', 'other'
                           )),
  inferred_place           text,
  inferred_activity        text,                                       -- 'walking' | 'driving' | etc.
  raw_payload              jsonb NOT NULL DEFAULT '{}',
  source_acquisition_id    uuid REFERENCES acquisitions(id)
);

CREATE INDEX location_pings_subject_time_idx ON location_pings(subject_party_id, observed_at);
CREATE INDEX location_pings_geog_idx ON location_pings USING GIST (geog);
CREATE INDEX location_pings_observed_idx ON location_pings(observed_at);
CREATE INDEX location_pings_source_idx ON location_pings(source_kind);

-- ----------------------------------------------------------------------------
-- place_observations: derived dwellings / frequent places.  Materialized
-- summary so "where was X most often during Y" queries are fast.
-- ----------------------------------------------------------------------------

CREATE TABLE place_observations (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_party_id         uuid REFERENCES parties(id),
  place_label              text NOT NULL,
  centroid                 geography(Point, 4326) NOT NULL,
  radius_m                 int NOT NULL,
  observation_window_start timestamptz,
  observation_window_end   timestamptz,
  visit_count              int NOT NULL DEFAULT 0,
  total_dwell_minutes      int NOT NULL DEFAULT 0,
  derived_from             text[] NOT NULL DEFAULT '{}',              -- contributing source_kinds
  computed_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX place_obs_subject_idx ON place_observations(subject_party_id);
CREATE INDEX place_obs_centroid_idx ON place_observations USING GIST (centroid);

-- ----------------------------------------------------------------------------
-- health_records: per-sample data from Apple Health / Google Fit exports.
-- Volumes can be enormous; ingest selectively.
-- ----------------------------------------------------------------------------

CREATE TABLE health_records (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_party_id    uuid REFERENCES parties(id),
  data_type           text NOT NULL,                                 -- 'HKQuantityTypeIdentifierHeartRate' etc.
  value               numeric,
  unit                text,
  start_at            timestamptz NOT NULL,
  end_at              timestamptz,
  source_device       text,                                          -- 'iPhone' | 'Apple Watch' | 'Manual'
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX health_records_subject_time_idx ON health_records(subject_party_id, data_type, start_at);

CREATE TABLE workout_routes (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_party_id    uuid REFERENCES parties(id),
  workout_kind        text,                                          -- 'running' | 'cycling' | 'walking' | etc.
  start_at            timestamptz NOT NULL,
  end_at              timestamptz NOT NULL,
  track               geography(LineStringZM, 4326),
  distance_m          numeric,
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX workout_routes_subject_idx ON workout_routes(subject_party_id, start_at);
CREATE INDEX workout_routes_track_idx ON workout_routes USING GIST (track);

-- ----------------------------------------------------------------------------
-- wifi_associations: networks the device joined, with timestamps.  BSSID
-- enables geolocation against public databases (Wigle, etc.).
-- ----------------------------------------------------------------------------

CREATE TABLE wifi_associations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ssid                text,
  bssid               text,
  associated_at       timestamptz NOT NULL,
  disassociated_at    timestamptz,
  geolocated_lat      double precision,
  geolocated_lng      double precision,
  geolocated_geog     geography(Point, 4326),
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX wifi_assoc_device_idx ON wifi_associations(device_id, associated_at);
CREATE INDEX wifi_assoc_bssid_idx ON wifi_associations(bssid) WHERE bssid IS NOT NULL;
CREATE INDEX wifi_assoc_geog_idx ON wifi_associations USING GIST (geolocated_geog)
  WHERE geolocated_geog IS NOT NULL;

CREATE TABLE bluetooth_encounters (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  peer_name           text,
  peer_address        text,                                          -- MAC
  first_seen_at       timestamptz,
  last_seen_at        timestamptz,
  rssi_avg            numeric,
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX bt_encounters_device_idx ON bluetooth_encounters(device_id, first_seen_at);
CREATE INDEX bt_encounters_peer_idx ON bluetooth_encounters(peer_address) WHERE peer_address IS NOT NULL;

-- ----------------------------------------------------------------------------
-- account_sign_ins: Apple ID / Google / Meta / Microsoft sign-in events.
-- Forensically valuable for showing when an account was actually accessed.
-- ----------------------------------------------------------------------------

CREATE TABLE account_sign_ins (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id            uuid REFERENCES parties(id),
  service             text NOT NULL,                                 -- 'apple_id' | 'google' | 'meta' | etc.
  signed_in_at        timestamptz NOT NULL,
  ip_address          inet,
  user_agent          text,
  device_descriptor   text,
  result              text NOT NULL CHECK (result IN (
                        'success', 'failed', 'mfa_challenge',
                        'logout', 'recovery', 'session_revoked'
                      )),
  geo_inferred        text,
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX sign_ins_party_time_idx ON account_sign_ins(party_id, signed_in_at);
CREATE INDEX sign_ins_service_idx ON account_sign_ins(service, signed_in_at);
CREATE INDEX sign_ins_ip_idx ON account_sign_ins(ip_address);

-- ----------------------------------------------------------------------------
-- browser_history.  Time-density evidence; cheap to store, useful to query.
-- ----------------------------------------------------------------------------

CREATE TABLE browser_history (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           uuid REFERENCES devices(id),
  party_id            uuid REFERENCES parties(id),
  url                 text NOT NULL,
  title               text,
  visited_at          timestamptz NOT NULL,
  visit_duration_s    int,
  referrer            text,
  visit_type          text,                                          -- 'typed' | 'link' | 'reload' | etc.
  browser             text,                                          -- 'safari' | 'chrome' | 'firefox' | etc.
  source_acquisition_id uuid REFERENCES acquisitions(id),
  url_tsv             tsvector GENERATED ALWAYS AS (
                        to_tsvector('english',
                          coalesce(title, '') || ' ' || url)
                      ) STORED
);

CREATE INDEX browser_history_party_time_idx ON browser_history(party_id, visited_at);
CREATE INDEX browser_history_url_trgm_idx ON browser_history USING GIN (url gin_trgm_ops);
CREATE INDEX browser_history_tsv_idx ON browser_history USING GIN (url_tsv);

-- ----------------------------------------------------------------------------
-- notes: Apple Notes, Google Keep, similar.  These are documents, but
-- structured enough to warrant first-class storage.
-- ----------------------------------------------------------------------------

CREATE TABLE notes (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid REFERENCES matters(id),
  party_id            uuid REFERENCES parties(id),
  platform            text NOT NULL CHECK (platform IN (
                        'apple_notes', 'google_keep', 'evernote',
                        'notion', 'obsidian', 'plain_text', 'other'
                      )),
  external_id         text,
  folder_path         text,
  title               text,
  body                text,
  body_tsv            tsvector GENERATED ALWAYS AS (
                        to_tsvector('english',
                          coalesce(title, '') || ' ' || coalesce(body, ''))
                      ) STORED,
  created_at_external timestamptz,
  modified_at_external timestamptz,
  has_attachments     boolean NOT NULL DEFAULT false,
  source_acquisition_id uuid REFERENCES acquisitions(id),
  pii_tier            text NOT NULL DEFAULT 'sensitive'
                        CHECK (pii_tier IN (
                          'public', 'low', 'internal', 'sensitive',
                          'privileged', 'work_product'
                        )),
  ingested_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX notes_party_idx ON notes(party_id);
CREATE INDEX notes_modified_idx ON notes(modified_at_external);
CREATE INDEX notes_body_tsv_idx ON notes USING GIN (body_tsv);

-- ----------------------------------------------------------------------------
-- social_posts: Facebook posts/comments, etc.  Reactions live in
-- message_associations style table below.
-- ----------------------------------------------------------------------------

CREATE TABLE social_posts (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matter_id           uuid REFERENCES matters(id),
  party_id            uuid REFERENCES parties(id),
  platform            text NOT NULL CHECK (platform IN (
                        'facebook', 'instagram', 'twitter_x',
                        'linkedin', 'tiktok', 'reddit', 'other'
                      )),
  external_id         text,
  parent_post_id      uuid REFERENCES social_posts(id),               -- for comments
  kind                text NOT NULL CHECK (kind IN (
                        'post', 'comment', 'reply', 'share', 'reaction',
                        'story', 'reel', 'check_in'
                      )),
  body                text,
  posted_at           timestamptz,
  visibility          text,
  url                 text,
  source_acquisition_id uuid REFERENCES acquisitions(id),
  body_tsv            tsvector GENERATED ALWAYS AS (
                        to_tsvector('english', coalesce(body, ''))
                      ) STORED,
  ingested_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX social_posts_party_idx ON social_posts(party_id, posted_at);
CREATE INDEX social_posts_platform_idx ON social_posts(platform, posted_at);
CREATE INDEX social_posts_parent_idx ON social_posts(parent_post_id) WHERE parent_post_id IS NOT NULL;
CREATE INDEX social_posts_body_tsv_idx ON social_posts USING GIN (body_tsv);

-- ----------------------------------------------------------------------------
-- activity_events: search queries, voice-assistant commands, YouTube views.
-- Highly granular behavioral data from Google "My Activity", Apple Siri,
-- etc.  Often the most damaging discoverable category of all.
-- ----------------------------------------------------------------------------

CREATE TABLE activity_events (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id            uuid REFERENCES parties(id),
  service             text NOT NULL,                                 -- 'google_search' | 'siri' | 'alexa' | 'youtube_watch' | etc.
  occurred_at         timestamptz NOT NULL,
  text                text,
  url                 text,
  product             text,
  raw_payload         jsonb NOT NULL DEFAULT '{}',
  source_acquisition_id uuid REFERENCES acquisitions(id),
  text_tsv            tsvector GENERATED ALWAYS AS (
                        to_tsvector('english', coalesce(text, ''))
                      ) STORED,
  pii_tier            text NOT NULL DEFAULT 'sensitive'
                        CHECK (pii_tier IN (
                          'public', 'low', 'internal', 'sensitive',
                          'privileged', 'work_product'
                        ))
);

CREATE INDEX activity_party_time_idx ON activity_events(party_id, occurred_at);
CREATE INDEX activity_service_idx ON activity_events(service, occurred_at);
CREATE INDEX activity_text_tsv_idx ON activity_events USING GIN (text_tsv);

-- ----------------------------------------------------------------------------
-- tracking_disclosures: Off-Facebook Activity and similar — third parties
-- that shared data ABOUT you with a platform.  Useful for showing
-- inferred associations.
-- ----------------------------------------------------------------------------

CREATE TABLE tracking_disclosures (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id            uuid REFERENCES parties(id),
  platform            text NOT NULL,                                 -- 'facebook'
  disclosing_third_party text NOT NULL,                              -- 'WalmartApp', 'GMC.com', etc.
  event_type          text,                                          -- 'CUSTOM' | 'PURCHASE' | 'VIEW_CONTENT' | etc.
  occurred_at         timestamptz,
  raw_payload         jsonb NOT NULL DEFAULT '{}',
  source_acquisition_id uuid REFERENCES acquisitions(id)
);

CREATE INDEX tracking_party_time_idx ON tracking_disclosures(party_id, occurred_at);
CREATE INDEX tracking_third_party_idx ON tracking_disclosures(disclosing_third_party);

-- ----------------------------------------------------------------------------
-- device_telemetry_query_jobs: targeted extraction requests so the
-- ingestion of knowledgeC and similar massive sources is auditable and
-- scope-limited.
-- ----------------------------------------------------------------------------

CREATE TABLE device_telemetry_query_jobs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id           uuid NOT NULL REFERENCES devices(id),
  acquisition_id      uuid NOT NULL REFERENCES acquisitions(id),    -- the underlying backup
  time_range          tstzrange NOT NULL,
  streams             text[] NOT NULL,
  reason              text NOT NULL,                                 -- factual dispute being investigated
  requested_by_actor  uuid REFERENCES actors(id),
  status              text NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'in_progress', 'completed', 'failed'
                      )),
  completed_at        timestamptz,
  rows_emitted        int,
  notes               text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX dtq_jobs_device_idx ON device_telemetry_query_jobs(device_id);
