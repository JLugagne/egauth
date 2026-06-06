CREATE TABLE IF NOT EXISTS mfa_totp (
    tenant_id VARCHAR NOT NULL,
    user_id UUID NOT NULL,
    secret VARCHAR NOT NULL,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    last_used_step BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    tenant_id VARCHAR NOT NULL,
    user_id UUID NOT NULL,
    code_hash VARCHAR NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes (tenant_id, user_id);
