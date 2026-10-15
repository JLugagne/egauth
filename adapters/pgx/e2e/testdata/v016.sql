-- A v0.16 database: the v0.16 schema (every v0.16 migration, in order) and sample rows. Loaded by the G29 legacy upgrade test.
-- Secrets are sealed with the v0.16 KEK in testdata/v016_key.hex (copied from kek/testdata/v016_fixtures.json in the core module). Do not edit by hand.

-- v0.16 migration: identity/migrations/001_create_tables.sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_users_email_tenant ON users (tenant_id, email) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL,
    provider VARCHAR NOT NULL,
    provider_id VARCHAR NOT NULL,
    password_hash VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX idx_identities_provider_tenant ON identities (tenant_id, provider, provider_id);

-- v0.16 migration: identity/migrations/002_add_account_lockout.sql
ALTER TABLE identities ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE NULL;

-- v0.16 migration: identity/migrations/003_create_verification_tokens.sql
CREATE TABLE IF NOT EXISTS verification_tokens (
    selector VARCHAR PRIMARY KEY,
    verifier_hash VARCHAR NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL,
    kind VARCHAR NOT NULL,
    metadata BYTEA,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_tokens_user ON verification_tokens (tenant_id, user_id, kind);

-- v0.16 migration: identity/migrations/004_add_phone.sql
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

-- v0.16 migration: identity/migrations/005_add_recovery_email.sql
-- Adds an optional, independently-verified recovery email — a SECONDARY contact channel distinct
-- from the primary login email, used for account recovery. It breaks the single-email takeover
-- chain (a compromised primary mailbox no longer implies a lost account). Unlike the primary
-- email it is NOT a login key and is intentionally NOT globally unique (several accounts may share
-- a recovery contact, e.g. a family), so no unique index is created.
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_email VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_email_verified_at TIMESTAMP WITH TIME ZONE;

-- v0.16 migration: identity/migrations/006_add_disabled_at.sql
-- Adds an optional administrative-disable timestamp. A disabled account is a REVERSIBLE
-- suspension distinct from the soft delete (deleted_at): the row, its email slot and all
-- associated data are retained so the account can be re-enabled, but authentication is refused
-- while disabled_at is set. NULL means the account is active. The column is nullable with no
-- default, so existing rows are active after the migration.
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMP WITH TIME ZONE;

-- v0.16 migration: identity/migrations/007_add_expires_at_index.sql
CREATE INDEX IF NOT EXISTS idx_verification_tokens_tenant_expires ON verification_tokens (tenant_id, expires_at);

-- v0.16 migration: identity/migrations/008_add_password_change_columns.sql
-- Adds password-change tracking columns to the identities table.
--
-- password_changed_at: informational audit metadata recording when the
--   password hash was last set. NULL means the change time is unknown
--   (e.g. a legacy credential). It drives no behavior — egauth has no
--   age-based password rotation.
--
-- must_change_password: advisory flag set when an admin provisions a
--   temporary/one-time credential (AdminCreateUser, SetTemporaryPassword).
--   It never blocks authentication; it causes the next login to issue a
--   flagged, access-only token that soft-redirects to the password-change
--   page. Cleared automatically on a successful UpdateIdentityPassword write.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- v0.16 migration: keystore/migrations/001_create_keystore_keys_table.sql
-- Per-tenant signing keys for github.com/JLugagne/egauth/keystore.
-- The `secret` column holds the KEK-sealed (envelope-encrypted) HMAC secret, never plaintext —
-- the keystore.Manager seals before insert and opens after read. A database dump alone therefore
-- yields no usable signing material.
CREATE TABLE IF NOT EXISTS keystore_keys (
    tenant_id  TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    secret     BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- not_after: instant past which the key must no longer sign or verify and is eligible for
    -- reaping. NULL means no expiry.
    not_after  TIMESTAMPTZ NULL,
    -- retired_at: when set, the key is verify-only (it no longer signs new tokens) — set on the
    -- previous key during a graceful renewal so outstanding tokens keep validating during overlap.
    retired_at TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, key_id)
);

-- Active-key lookup: newest non-retired, non-expired key per tenant.
CREATE INDEX IF NOT EXISTS idx_keystore_keys_active
    ON keystore_keys (tenant_id, created_at DESC)
    WHERE retired_at IS NULL;

-- v0.16 migration: keystore/migrations/002_add_key_algorithm.sql
-- Add the signing algorithm column. Existing rows are HMAC (HS256); the secret column for an
-- asymmetric key holds the sealed PKCS#8 DER of the private key instead of a raw HMAC secret.
ALTER TABLE keystore_keys ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'HS256';

-- v0.16 migration: mfa/migrations/001_create_mfa_tables.sql
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

-- v0.16 migration: mfa/migrations/002_add_totp_failed_attempts.sql
-- Adds a failed-verification counter to each TOTP factor so the second factor is not
-- online-brute-forceable. The service reserves a slot (IncrementTOTPAttempts) before the
-- constant-time compare and locks the factor once the count exceeds the configured ceiling;
-- a successful TOTP or recovery-code verification resets it to zero. Limiting is ON by default.
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;

-- v0.16 migration: mfa/migrations/003_add_totp_last_attempt_at.sql
-- Adds a last_attempt_at timestamp to each TOTP factor so the service can implement
-- time-based lockout decay: once the elapsed time since the last failed attempt exceeds
-- the configured LockoutDuration, the failed-attempt counter is automatically reset and
-- the factor becomes usable again without operator intervention.
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMP WITH TIME ZONE;

-- v0.16 migration: mfa/migrations/004_add_recovery_attempts.sql
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

-- v0.16 migration: oauth/migrations/001_init.sql
CREATE TABLE IF NOT EXISTS oauth_oidc_providers (
    tenant_id VARCHAR(255) NOT NULL,
    provider_name VARCHAR(255) NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    auth_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    issuer TEXT NOT NULL,
    jwks_url TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider_name)
);

-- v0.16 migration: otp/migrations/001_create_otp_codes.sql
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

-- v0.16 migration: otp/migrations/002_add_expires_at_index.sql
CREATE INDEX IF NOT EXISTS idx_otp_codes_tenant_expires ON otp_codes (tenant_id, expires_at);

-- v0.16 migration: otp/migrations/003_create_otp_issuances.sql
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

-- v0.16 migration: passkey/migrations/001_create_passkey_credentials.sql
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

-- v0.16 migration: passkey/migrations/002_add_credential_management_metadata.sql
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS nickname TEXT NOT NULL DEFAULT '';
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS transports TEXT[];
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS backup_state BOOLEAN NOT NULL DEFAULT false;

-- v0.16 migration: passkey/migrations/003_create_passkey_challenges.sql
CREATE TABLE IF NOT EXISTS passkey_challenges (
    tenant_id VARCHAR NOT NULL,
    challenge VARCHAR NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, challenge)
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges (expires_at);

-- v0.16 migration: sessions/migrations/001_create_sessions_table.sql
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT,
    ip TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_tenant_token_hash ON sessions(tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- v0.16 migration: sessions/migrations/002_add_expires_at_index.sql
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_expires ON sessions (tenant_id, expires_at);

-- v0.16 migration: tokens/migrations/001_create_tokens_table.sql
CREATE TABLE IF NOT EXISTS tokens (
    id UUID,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    user_id UUID NOT NULL,
    prefix TEXT,
    claims JSONB,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, token_hash)
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);

-- v0.16 migration: tokens/migrations/002_add_refresh_token_rotation.sql
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS family_id UUID;
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_tokens_family_id ON tokens(tenant_id, family_id) WHERE claims IS NULL;

-- v0.16 migration: tokens/migrations/003_add_refresh_token_auth_time.sql
-- auth_time anchors step-up / "sudo mode" freshness: the time the subject actually
-- authenticated, preserved across refresh-token rotation (unlike the per-token created_at).
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ NULL;

-- v0.16 migration: tokens/migrations/004_add_expires_at_index.sql
CREATE INDEX IF NOT EXISTS idx_tokens_tenant_expires ON tokens (tenant_id, expires_at);

-- v0.16 migration: tokens/migrations/005_add_refresh_token_must_change_password.sql
-- must_change_password gates a rotation family on a forced password change. It is set on the
-- initial pair for a flagged (admin-provisioned/temporary) credential and carried verbatim onto
-- every rotated descendant, so the forced-change soft gate survives every silent refresh and the
-- user cannot escape it by waiting for the access token to expire. Cleared only by a fresh login.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- v0.16 migration: tokens/migrations/006_add_api_key_type_and_created_by.sql
-- type classifies the key as a PAT (personal access token, human) or a service token (machine).
-- Existing rows pre-date this column; they are assumed to be service tokens (the more restricted
-- machine-identity default), which avoids silently granting human-principal status to legacy keys.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'service';

-- created_by records the uuid of the human who issued the key. NULL is valid for legacy rows
-- and for keys whose creator is not tracked.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS created_by UUID NULL;

-- v0.16 migration: tokens/migrations/007_add_api_key_revoked_at.sql
-- revoked_at marks a key as soft-revoked. NULL means the key is active; a non-NULL timestamp
-- records when the key was administratively revoked. Existing rows default to NULL (active).
-- FindAPIKeyByHash still returns revoked keys with this field populated; the verify layer
-- maps a non-NULL revoked_at to ErrAPIKeyRevoked so revoked keys stay visible to management
-- tooling and produce a distinct error from not-found.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;

-- v0.16 migration: tokens/migrations/008_add_refresh_token_amr.sql
-- AMR (RFC 8176 authentication method references) proved when the rotation family was minted.
-- It is copied onto every rotated descendant so a stepped-up session keeps its assurance across a
-- silent refresh instead of decaying to an empty AMR (F-COMP-004). Stored as JSONB, matching the
-- claims column encoding. NULL marks a legacy row minted before the field existed and MUST read
-- back as a nil slice (never coerced to an empty one), so "no recorded assurance" stays
-- distinguishable from "assurance = []".
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS amr JSONB NULL;

-- v0.16 migration: tokens/migrations/009_add_refresh_token_remember_me.sql
-- remember_me records whether the rotation family was minted with "remember me". It is set on the
-- initial pair and carried verbatim onto every rotated descendant, so the refresh cookie keeps the
-- persistence the user chose at login instead of reverting to a session cookie on the first
-- silent refresh. Legacy rows default to false (session cookie), their previous behavior.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS remember_me BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE schema_migrations (
    version    text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES
 ('001_create_tables.sql'), ('002_add_account_lockout.sql'), ('003_create_verification_tokens.sql'),
 ('004_add_phone.sql'), ('005_add_recovery_email.sql'), ('006_add_disabled_at.sql'),
 ('007_add_expires_at_index.sql'), ('008_add_password_change_columns.sql'),
 ('001_create_keystore_keys_table.sql'), ('002_add_key_algorithm.sql'),
 ('001_create_mfa_tables.sql'), ('002_add_totp_failed_attempts.sql'), ('003_add_totp_last_attempt_at.sql'),
 ('004_add_recovery_attempts.sql'), ('001_init.sql'),
 ('001_create_otp_codes.sql'), ('002_add_expires_at_index.sql'), ('003_create_otp_issuances.sql'),
 ('001_create_passkey_credentials.sql'), ('002_add_credential_management_metadata.sql'),
 ('003_create_passkey_challenges.sql'), ('001_create_sessions_table.sql'),
 ('001_create_tokens_table.sql'), ('002_add_refresh_token_rotation.sql'), ('003_add_refresh_token_auth_time.sql'),
 ('004_add_expires_at_index.sql'), ('005_add_refresh_token_must_change_password.sql'),
 ('006_add_api_key_type_and_created_by.sql'), ('007_add_api_key_revoked_at.sql'),
 ('008_add_refresh_token_amr.sql'), ('009_add_refresh_token_remember_me.sql');

INSERT INTO users (id, tenant_id, email, email_verified_at, created_at, updated_at) VALUES
 ('6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', 'tenant-a', 'alice@example.test', now() - interval '30 days', now() - interval '30 days', now() - interval '1 day'),
 ('0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'tenant-a', 'bob@example.test', now() - interval '20 days', now() - interval '20 days', now() - interval '2 days');

INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, password_hash, created_at, updated_at, password_changed_at) VALUES
 ('a1111111-1111-4111-8111-111111111111', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', 'tenant-a', 'password', 'alice@example.test',
  '$argon2id$v=19$m=65536,t=1,p=4$WEyrcG3YzHqrxCmGQiDnAg$/m2Qs8JNlp2z3RExsY+7OTZD4A1vWgJQsl1JIUbP4gw', now() - interval '30 days', now() - interval '30 days', now() - interval '30 days'),
 ('a2222222-2222-4222-8222-222222222222', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'tenant-a', 'password', 'bob@example.test',
  '$argon2id$v=19$m=65536,t=1,p=4$WEyrcG3YzHqrxCmGQiDnAg$/m2Qs8JNlp2z3RExsY+7OTZD4A1vWgJQsl1JIUbP4gw', now() - interval '20 days', now() - interval '20 days', now() - interval '20 days'),
 ('a3333333-3333-4333-8333-333333333333', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'tenant-a', 'google', 'google-sub-bob', NULL, now() - interval '19 days', now() - interval '19 days', NULL);

INSERT INTO verification_tokens (selector, verifier_hash, user_id, tenant_id, kind, metadata, expires_at, created_at) VALUES
 ('sel-1', 'deadbeef', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'tenant-a', 'email_verify', NULL, now() + interval '1 day', now());

INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, created_at) VALUES
 ('tenant-a', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', replace(encode(decode('49ebc6a006ef737f1e01ed9ca478200ca28f3594980b5bb207c1e32e56299c0754bb98e9d2a6ff2a7bfc43106c87f4ba9ea4f57fa4a8910ca8002b6d', 'hex'), 'base64'), E'\n', ''), now() - interval '29 days', 0, now() - interval '29 days');

INSERT INTO mfa_recovery_codes (tenant_id, user_id, code_hash, used_at, created_at) VALUES
 ('tenant-a', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', 'recovery-hash-1', NULL, now() - interval '29 days'),
 ('tenant-a', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', 'recovery-hash-2', now() - interval '3 days', now() - interval '29 days');

INSERT INTO mfa_recovery_attempts (tenant_id, user_id, failed_attempts, last_attempt_at) VALUES
 ('tenant-a', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', 1, now() - interval '3 days');

INSERT INTO oauth_oidc_providers (tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes) VALUES
 ('tenant-a', 'google', 'client-id-1', replace(encode(decode('9d664105e87f399333be5b7505c92c48e14be44e402b3b4b1d2beefc0184e8ea6306754e257ef5770f82b43e44ae013b9c58ad39a320c1ec2c1c7c', 'hex'), 'base64'), E'\n', ''), 'https://idp.example.test/authorize',
  'https://idp.example.test/token', 'https://idp.example.test', 'https://idp.example.test/jwks', 'openid email');

INSERT INTO keystore_keys (tenant_id, key_id, secret, alg) VALUES
 ('tenant-a', 'k-fixture-1', decode('7836163b132babcb5fcbe208c53d8f370957affde6618272b1048cc69d1e30a1f0c279bc947bd6b377d53f5aa5b246fadfa4a3b197d114234b1d8418f170b01dd4', 'hex'), 'HS256');

INSERT INTO passkey_credentials (tenant_id, user_id, credential_id, public_key, sign_count, data, created_at, nickname, transports) VALUES
 ('tenant-a', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', decode('0102030405060708', 'hex'), decode('a501020326', 'hex'), 4,
  decode('7b7d', 'hex'), now() - interval '10 days', 'laptop', ARRAY['internal']);

INSERT INTO passkey_challenges (tenant_id, challenge, expires_at) VALUES ('tenant-a', 'challenge-1', now() + interval '5 minutes');

INSERT INTO otp_codes (tenant_id, subject_id, purpose, code_hash, attempts, expires_at, created_at) VALUES
 ('tenant-a', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'login', 'otp-hash', 0, now() + interval '5 minutes', now());

INSERT INTO otp_issuances (tenant_id, subject_id, purpose, last_issued_at) VALUES
 ('tenant-a', '0b7e9f10-2a3c-4d5e-9f60-718293a4b5c6', 'login', now());

INSERT INTO sessions (id, tenant_id, user_id, token_hash, user_agent, ip, expires_at) VALUES
 ('5e551011-0000-4000-8000-000000000001', 'tenant-a', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5',
  encode(sha256(convert_to('v016-session-secret', 'UTF8')), 'hex'), 'curl', '192.0.2.1', now() + interval '7 days');

INSERT INTO tokens (id, tenant_id, token_hash, user_id, prefix, claims, expires_at, family_id, consumed_at, auth_time, amr, remember_me) VALUES
 ('7a000000-0000-4000-8000-000000000001', 'tenant-a', encode(sha256(convert_to('v016-refresh-live', 'UTF8')), 'hex'),
  '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', NULL, NULL, now() + interval '7 days', 'fa000000-0000-4000-8000-000000000001', NULL, now() - interval '1 hour', '["pwd"]', false),
 ('7a000000-0000-4000-8000-000000000002', 'tenant-a', encode(sha256(convert_to('v016-refresh-consumed', 'UTF8')), 'hex'),
  '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', NULL, NULL, now() + interval '7 days', 'fa000000-0000-4000-8000-000000000002', now() - interval '1 hour', now() - interval '2 hours', '["pwd"]', false),
 ('7a000000-0000-4000-8000-000000000003', 'tenant-a', encode(sha256(convert_to('v016-refresh-laundered', 'UTF8')), 'hex'),
  '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5', NULL, NULL, now() + interval '7 days', 'fa000000-0000-4000-8000-000000000002', NULL, now() - interval '2 hours', '["pwd","mfa","otp"]', true);

INSERT INTO tokens (id, tenant_id, token_hash, user_id, prefix, claims, type, created_by) VALUES
 ('4b000000-0000-4000-8000-000000000001', 'tenant-a', encode(sha256(convert_to('egk_v016-api-key-secret', 'UTF8')), 'hex'),
  '4b000000-0000-4000-8000-000000000001', 'egk', '{"Roles":["service"],"Scopes":["report:read"]}'::jsonb, 'service', '6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5');
