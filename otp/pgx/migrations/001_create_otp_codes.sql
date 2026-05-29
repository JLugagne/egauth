CREATE TABLE IF NOT EXISTS otp_codes (
    tenant_id VARCHAR NOT NULL,
    subject_id UUID NOT NULL,
    purpose VARCHAR NOT NULL,
    code_hash VARCHAR NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, subject_id, purpose)
);
