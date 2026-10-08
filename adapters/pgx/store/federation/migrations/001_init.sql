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
