ALTER TABLE tokens ADD COLUMN IF NOT EXISTS family_id UUID;
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_tokens_family_id ON tokens(tenant_id, family_id) WHERE claims IS NULL;
