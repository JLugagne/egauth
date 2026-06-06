CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT,
    ip TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_tenant_token_hash ON sessions(tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
