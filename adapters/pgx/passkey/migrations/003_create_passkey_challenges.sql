CREATE TABLE IF NOT EXISTS passkey_challenges (
    tenant_id VARCHAR NOT NULL,
    challenge VARCHAR NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, challenge)
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at ON passkey_challenges (expires_at);
