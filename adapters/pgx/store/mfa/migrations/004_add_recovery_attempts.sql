-- Adds a recovery attempts table to track failed recovery code verifications
-- independently of TOTP factors (SEC-MFA-05). An attacker exhausting TOTP failed
-- attempts cannot lock out legitimate users holding valid recovery codes.
CREATE TABLE IF NOT EXISTS mfa_recovery_attempts (
    tenant_id VARCHAR NOT NULL,
    user_id UUID NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (tenant_id, user_id)
);
