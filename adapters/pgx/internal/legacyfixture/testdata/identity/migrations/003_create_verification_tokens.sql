CREATE TABLE IF NOT EXISTS verification_tokens (
    selector VARCHAR PRIMARY KEY,
    verifier_hash VARCHAR NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL,
    kind VARCHAR NOT NULL,
    metadata BYTEA,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_tokens_user ON verification_tokens (tenant_id, user_id, kind);
