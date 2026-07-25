-- FindIdentitiesByUserID (the per-login identity lookup) filters on WHERE user_id = $1 AND
-- tenant_id = $2. Without this index the only usable index is
-- idx_identities_provider_tenant (tenant_id, provider, provider_id), which does not cover a
-- user_id lookup, so it degenerates to a full sequential scan of the identities table.
CREATE INDEX IF NOT EXISTS idx_identities_user_tenant ON identities (tenant_id, user_id);
