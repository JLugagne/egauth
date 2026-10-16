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
