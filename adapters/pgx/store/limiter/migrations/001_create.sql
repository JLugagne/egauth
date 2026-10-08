CREATE UNLOGGED TABLE IF NOT EXISTS egauth_ratelimit (
    key        BYTEA            PRIMARY KEY,
    tokens     DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ      NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_ratelimit_updated_idx ON egauth_ratelimit (updated_at);
