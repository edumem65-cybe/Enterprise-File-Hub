-- DRAFT 0004: columns and tables the application layer needs (PostgresRepo, ADR-0007).

-- Upload sessions: the blob key chosen at session creation, the resulting version, and whether a file slot is reserved.
ALTER TABLE upload_sessions
  ADD COLUMN blob_key      text UNIQUE,
  ADD COLUMN version_id    uuid REFERENCES file_versions(id),
  ADD COLUMN reserved_file boolean NOT NULL DEFAULT true;
CREATE INDEX upload_sessions_version_idx ON upload_sessions (version_id) WHERE version_id IS NOT NULL;
CREATE INDEX upload_sessions_user_open_idx ON upload_sessions (user_id) WHERE state IN ('created','uploading','finalizing');

-- Alerts for super admins and the owner's region manager (scan rejected / failed).
CREATE TABLE alerts (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind            text NOT NULL CHECK (kind IN ('scan_infected','scan_failed','scan_limit')),
  file_version_id uuid NOT NULL REFERENCES file_versions(id),
  owner_id        uuid NOT NULL REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz
);
CREATE INDEX alerts_open_idx ON alerts (created_at) WHERE acknowledged_at IS NULL;

-- Delayed jobs (scan retries with backoff) go through the outbox.
ALTER TABLE outbox ADD COLUMN available_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX outbox_ready_idx ON outbox (available_at) WHERE processed_at IS NULL;
