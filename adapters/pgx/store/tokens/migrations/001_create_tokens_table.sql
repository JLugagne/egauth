CREATE TABLE IF NOT EXISTS tokens (
    id UUID,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    user_id UUID NOT NULL,
    prefix TEXT,
    claims JSONB,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, token_hash)
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
