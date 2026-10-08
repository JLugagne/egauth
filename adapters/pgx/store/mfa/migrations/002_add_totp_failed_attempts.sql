-- Adds a failed-verification counter to each TOTP factor so the second factor is not
-- online-brute-forceable. The service reserves a slot (IncrementTOTPAttempts) before the
-- constant-time compare and locks the factor once the count exceeds the configured ceiling;
-- a successful TOTP or recovery-code verification resets it to zero. Limiting is ON by default.
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
