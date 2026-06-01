-- Adds an optional, verifiable phone number to accounts (lower-assurance contact / recovery
-- channel; NIST SP 800-63B excludes SMS as an authentication factor, so this is NOT an MFA
-- factor). Phone is unique per tenant among live accounts, mirroring the email uniqueness index.
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMP WITH TIME ZONE;

-- Partial unique index: a phone is unique per tenant across live (non-deleted) accounts, and the
-- WHERE clause also lets NULL phones coexist freely (accounts without a verified number).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_tenant
    ON users (tenant_id, phone)
    WHERE deleted_at IS NULL AND phone IS NOT NULL;
