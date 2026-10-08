ALTER TABLE keystore_keys ADD COLUMN IF NOT EXISTS aad_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE keystore_keys ADD COLUMN IF NOT EXISTS seq BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE UNIQUE INDEX IF NOT EXISTS egauth_keystore_keys_seq_idx ON keystore_keys (seq);

CREATE INDEX IF NOT EXISTS egauth_keystore_keys_not_after_idx ON keystore_keys (not_after) WHERE not_after IS NOT NULL;

CREATE TABLE IF NOT EXISTS egauth_tenant_tombstones (
    tenant_id TEXT        PRIMARY KEY,
    erased_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS egauth_key_changes (
    seq        BIGSERIAL   PRIMARY KEY,
    tenant_id  TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS egauth_key_changes_created_idx ON egauth_key_changes (created_at);

CREATE TABLE IF NOT EXISTS egauth_key_feed_horizon (
    id             SMALLINT PRIMARY KEY CHECK (id = 1),
    pruned_through BIGINT   NOT NULL
);
