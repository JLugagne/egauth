-- Adds an optional, independently-verified recovery email — a SECONDARY contact channel distinct
-- from the primary login email, used for account recovery. It breaks the single-email takeover
-- chain (a compromised primary mailbox no longer implies a lost account). Unlike the primary
-- email it is NOT a login key and is intentionally NOT globally unique (several accounts may share
-- a recovery contact, e.g. a family), so no unique index is created.
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_email VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_email_verified_at TIMESTAMP WITH TIME ZONE;
