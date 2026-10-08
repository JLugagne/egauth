ALTER TABLE tokens ADD COLUMN IF NOT EXISTS app_claims BYTEA NULL;

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS created_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS name TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_tokens_api_key_id ON tokens (id) WHERE claims IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tokens_api_key_created_by ON tokens (tenant_id, created_by) WHERE claims IS NOT NULL;
