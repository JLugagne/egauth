-- Tenant records for github.com/JLugagne/egauth/keystore, independent of key rows.
--
-- Why a separate table: the keystore contract requires a backend to tell "unknown tenant"
-- (ErrTenantNotFound) apart from "known tenant with no usable key" (ErrNoActiveKey), because a
-- Manager with lazy provisioning MINTS a fresh signing key on ErrTenantNotFound. Deriving tenant
-- existence from the presence of key rows made an emergency RevokeTenantKeys — which deletes every
-- key row — look like an unknown tenant, so the next keyset resolution silently re-minted a key and
-- undid the revocation. RevokeTenantKeys now deletes key rows only; the tenant row survives until
-- DeleteTenant.
CREATE TABLE IF NOT EXISTS keystore_tenants (
    tenant_id  TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill from existing key material so an upgraded deployment keeps every tenant it already had.
INSERT INTO keystore_tenants (tenant_id, created_at)
SELECT tenant_id, MIN(created_at) FROM keystore_keys GROUP BY tenant_id
ON CONFLICT (tenant_id) DO NOTHING;

-- Enforce the invariant at the database level: no key row without its tenant record, and deleting a
-- tenant takes its keys with it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'keystore_keys_tenant_fkey') THEN
        ALTER TABLE keystore_keys
            ADD CONSTRAINT keystore_keys_tenant_fkey
            FOREIGN KEY (tenant_id) REFERENCES keystore_tenants (tenant_id) ON DELETE CASCADE;
    END IF;
END $$;
