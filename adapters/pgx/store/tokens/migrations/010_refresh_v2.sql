CREATE TABLE IF NOT EXISTS egauth_refresh_tokens (
    hash               BYTEA       PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    family_id          UUID        NOT NULL,
    lineage            UUID        NOT NULL,
    user_id            UUID        NOT NULL,
    attrs              BYTEA       NOT NULL,
    app_claims         BYTEA       NOT NULL,
    epoch              BIGINT      NOT NULL,
    client_fingerprint BYTEA       NULL,
    idle_expires_at    TIMESTAMPTZ NOT NULL,
    family_expires_at  TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ NULL,
    consumed_by        BYTEA       NULL,
    revoked_at         TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS egauth_refresh_tokens_family_idx ON egauth_refresh_tokens (tenant_id, family_id);

CREATE INDEX IF NOT EXISTS egauth_refresh_tokens_user_idx ON egauth_refresh_tokens (tenant_id, user_id);

CREATE INDEX IF NOT EXISTS egauth_refresh_tokens_family_expires_idx ON egauth_refresh_tokens (family_expires_at);

CREATE INDEX IF NOT EXISTS egauth_refresh_tokens_idle_expires_idx ON egauth_refresh_tokens (idle_expires_at);

CREATE TABLE IF NOT EXISTS egauth_revocations (
    seq        BIGSERIAL   PRIMARY KEY,
    tenant_id  TEXT        NOT NULL,
    family_id  UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_revocations_expires_idx ON egauth_revocations (expires_at);
