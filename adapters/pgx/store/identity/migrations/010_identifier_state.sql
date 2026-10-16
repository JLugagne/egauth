ALTER TABLE users ADD COLUMN IF NOT EXISTS identifier_state SMALLINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS egauth_users_legacy_identifiers_idx ON users (tenant_id, id) WHERE identifier_state <> 1;
