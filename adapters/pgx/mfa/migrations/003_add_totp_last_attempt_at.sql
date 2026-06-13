-- Adds a last_attempt_at timestamp to each TOTP factor so the service can implement
-- time-based lockout decay: once the elapsed time since the last failed attempt exceeds
-- the configured LockoutDuration, the failed-attempt counter is automatically reset and
-- the factor becomes usable again without operator intervention.
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMP WITH TIME ZONE;
