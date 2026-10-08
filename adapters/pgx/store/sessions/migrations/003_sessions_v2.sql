CREATE TABLE IF NOT EXISTS egauth_sessions (
    id                  UUID        PRIMARY KEY,
    token_hash          BYTEA       NOT NULL UNIQUE,
    tenant_id           TEXT        NOT NULL,
    user_id             UUID        NOT NULL,
    lineage             UUID        NOT NULL,
    attrs               BYTEA       NOT NULL,
    app_claims          BYTEA       NOT NULL,
    epoch               BIGINT      NOT NULL,
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    checked_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    client_fingerprint  BYTEA       NULL
);

CREATE INDEX IF NOT EXISTS egauth_sessions_user_idx ON egauth_sessions (tenant_id, user_id);

CREATE INDEX IF NOT EXISTS egauth_sessions_idle_expires_idx ON egauth_sessions (idle_expires_at);

CREATE INDEX IF NOT EXISTS egauth_sessions_absolute_expires_idx ON egauth_sessions (absolute_expires_at);

CREATE TABLE IF NOT EXISTS egauth_session_revocations (
    seq        BIGSERIAL   PRIMARY KEY,
    tenant_id  TEXT        NOT NULL,
    session_id UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_session_revocations_expires_idx ON egauth_session_revocations (expires_at);
