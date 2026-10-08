CREATE TABLE IF NOT EXISTS egauth_deployment (
    key        TEXT        PRIMARY KEY,
    sealed     BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS egauth_instances (
    instance_id  UUID        PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_instances_last_seen_idx ON egauth_instances (last_seen_at);
