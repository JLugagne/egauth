ALTER TABLE users ADD COLUMN IF NOT EXISTS security_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE identities ADD COLUMN IF NOT EXISTS provider_email TEXT NULL;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS provider_email_verified BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS egauth_identities_user_idx ON identities (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS egauth_epoch_log (
    seq        BIGSERIAL   PRIMARY KEY,
    tenant_id  TEXT        NOT NULL,
    user_id    UUID        NOT NULL,
    epoch      BIGINT      NOT NULL,
    reason     SMALLINT    NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_epoch_log_created_idx ON egauth_epoch_log (created_at);

CREATE INDEX IF NOT EXISTS egauth_epoch_log_tenant_idx ON egauth_epoch_log (tenant_id);

CREATE TABLE IF NOT EXISTS egauth_lifecycle_outbox (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    user_id         UUID        NOT NULL,
    event           SMALLINT    NOT NULL,
    payload         BYTEA       NOT NULL,
    subscriber      TEXT        NOT NULL,
    attempts        INT         NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    done_at         TIMESTAMPTZ NULL,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS egauth_lifecycle_outbox_due_idx ON egauth_lifecycle_outbox (next_attempt_at) WHERE done_at IS NULL;

CREATE INDEX IF NOT EXISTS egauth_lifecycle_outbox_subject_idx ON egauth_lifecycle_outbox (tenant_id, user_id) WHERE done_at IS NULL;

CREATE INDEX IF NOT EXISTS egauth_lifecycle_outbox_done_idx ON egauth_lifecycle_outbox (done_at) WHERE done_at IS NOT NULL;
