-- Issuance tombstones: the last instant a code was issued for a (tenant, subject, purpose).
-- Kept separate from otp_codes so the resend cooldown survives every terminal transition of the
-- code itself (consume, burn, delete, eviction, expiry): those DELETE otp_codes but must never
-- reset the throttle, or a burst of consume/reissue calls could bypass the cooldown (F-OTP-001).
-- Keyed like otp_codes so there is at most one live issuance per subject+purpose.
CREATE TABLE IF NOT EXISTS otp_issuances (
    tenant_id VARCHAR NOT NULL,
    subject_id UUID NOT NULL,
    purpose VARCHAR NOT NULL,
    last_issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, subject_id, purpose)
);

-- Backfill from outstanding codes so migrating live data keeps enforcing the cooldown from each
-- code's issuance instant. ON CONFLICT makes re-running the file harmless (pgxmigrate contract).
INSERT INTO otp_issuances (tenant_id, subject_id, purpose, last_issued_at)
SELECT tenant_id, subject_id, purpose, created_at FROM otp_codes
ON CONFLICT (tenant_id, subject_id, purpose) DO NOTHING;
