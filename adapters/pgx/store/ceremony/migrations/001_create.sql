CREATE TABLE IF NOT EXISTS egauth_ceremonies (
    tenant_id   TEXT        NOT NULL,
    kind        SMALLINT    NOT NULL,
    handle_hash BYTEA       NOT NULL,
    scope_hash  BYTEA       NOT NULL,
    sealed      BYTEA       NOT NULL,
    payload     BYTEA       NOT NULL,
    attempts    INT         NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, kind, handle_hash)
);

CREATE INDEX IF NOT EXISTS egauth_ceremonies_scope_idx ON egauth_ceremonies (tenant_id, kind, scope_hash, created_at);

CREATE INDEX IF NOT EXISTS egauth_ceremonies_tenant_scope_idx ON egauth_ceremonies (tenant_id, scope_hash);

CREATE INDEX IF NOT EXISTS egauth_ceremonies_expires_idx ON egauth_ceremonies (expires_at);

CREATE TABLE IF NOT EXISTS egauth_ceremony_consumed (
    tenant_id   TEXT        NOT NULL,
    kind        SMALLINT    NOT NULL,
    handle_hash BYTEA       NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, kind, handle_hash)
);

CREATE INDEX IF NOT EXISTS egauth_ceremony_consumed_expires_idx ON egauth_ceremony_consumed (expires_at);
