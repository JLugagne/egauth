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
