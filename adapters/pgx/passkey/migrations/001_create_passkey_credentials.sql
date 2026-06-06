CREATE TABLE IF NOT EXISTS passkey_credentials (
    tenant_id VARCHAR NOT NULL,
    user_id UUID NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    data BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_passkey_user ON passkey_credentials (tenant_id, user_id);
