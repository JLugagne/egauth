ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS aad_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS email_verification SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT '';

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS jwks_url TEXT NOT NULL DEFAULT '';

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS user_info_url TEXT NOT NULL DEFAULT '';

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS domains TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE oauth_oidc_providers ADD COLUMN IF NOT EXISTS seq BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE UNIQUE INDEX IF NOT EXISTS egauth_oauth_oidc_providers_seq_idx ON oauth_oidc_providers (seq);
