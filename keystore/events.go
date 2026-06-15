package keystore

import "github.com/JLugagne/egauth/event"

// Tenant-lifecycle event types emitted by a Manager through its event.Sink. They mirror the
// naming convention of the rest of egauth's event package. Emission is best-effort and nil-safe:
// with no sink configured, no events fire and the lifecycle still proceeds.
const (
	// EventTenantProvisioned fires after ProvisionTenant creates a new tenant's key material.
	EventTenantProvisioned event.Type = "tenant.provisioned"
	// EventTenantKeysRenewed fires after a successful key renewal (rotation with overlap).
	EventTenantKeysRenewed event.Type = "tenant.keys_renewed"
	// EventTenantKeysRevoked fires after every key for a tenant is immediately revoked.
	EventTenantKeysRevoked event.Type = "tenant.keys_revoked"
	// EventTenantDeleted fires after DeleteTenant purges a tenant's crypto and downstream
	// records.
	EventTenantDeleted event.Type = "tenant.deleted"
)
