// Package keystore provides per-tenant cryptographic isolation for egauth.
//
// In a multi-tenant deployment, no two tenants share signing material: every tenant gets its
// own JWT signing keyset, resolved per request through a KeyStore. A KeyStore is the
// Service/Store split used elsewhere in egauth — the Store persists key material, the Service
// layers the lifecycle (provision / renew / delete) and event emission on top.
//
// The empty tenant ID ("") is the single-tenant partition: a deployment that never calls
// ProvisionTenant with a non-empty ID behaves exactly like the static single-keyset mode,
// which remains the zero-config default of tokens/jwt. A KeyStore is opt-in.
//
// Key material persisted by a Store backend is encrypted at rest with a deployment KEK
// (envelope encryption); see KEK and NewManager. The KEK is required and fail-fast validated
// at construction.
package keystore

import (
	"context"
	"errors"
	"time"
)

// Errors returned across the keystore contract. They are sentinel values so callers can match
// with errors.Is regardless of the backend.
var (
	// ErrTenantMismatch is returned when a key record's tenant does not match the tenant the
	// operation is scoped to — the fail-closed guard against cross-tenant access.
	ErrTenantMismatch = errors.New("keystore: tenant mismatch")

	// ErrTenantNotFound is returned when an operation references a tenant that was never
	// provisioned (and lazy provisioning is disabled).
	ErrTenantNotFound = errors.New("keystore: tenant not found")

	// ErrTenantExists is returned by a strict provision when the tenant already exists. Callers
	// that want idempotent provisioning should use the Service's ProvisionTenant, which treats a
	// re-provision as a no-op success.
	ErrTenantExists = errors.New("keystore: tenant already exists")

	// ErrNoActiveKey is returned when a tenant exists but has no active (non-retired,
	// non-expired) signing key — for example after every key has been revoked.
	ErrNoActiveKey = errors.New("keystore: no active signing key for tenant")

	// ErrKeyNotFound is returned when a key ID does not resolve within a tenant.
	ErrKeyNotFound = errors.New("keystore: key not found")
)

// SigningKey is one tenant-scoped HS256 signing key. It maps directly onto tokens/jwt's keyset
// model: KeyID is stamped as the JWT "kid" header, Secret is the HMAC key.
//
// A key is the ACTIVE signer for its tenant when RetiredAt is nil and (NotAfter is zero or in
// the future). After renewal the previous key is kept verify-only (RetiredAt set) until its
// tokens expire — graceful, zero-downtime rollover. Revocation deletes keys outright.
type SigningKey struct {
	// KeyID is the unique-per-tenant identifier stamped as the JWT "kid".
	KeyID string
	// TenantID is the owning tenant ("" = single-tenant partition).
	TenantID string
	// Secret is the raw HMAC secret. Inside a Store backend it is held only in its
	// KEK-encrypted form; it is decrypted into this field by the Manager before use.
	Secret []byte
	// CreatedAt is when the key was minted.
	CreatedAt time.Time
	// NotAfter, when non-zero, is the instant past which the key must no longer verify tokens
	// and is eligible for retirement reaping. Zero means no expiry.
	NotAfter time.Time
	// RetiredAt, when non-nil, marks the key verify-only: it no longer signs new tokens but
	// keeps validating outstanding ones until NotAfter. Renewal sets this on the previous key.
	RetiredAt *time.Time
}

// IsActive reports whether the key may sign new tokens as of now: not retired and not past its
// NotAfter.
func (k SigningKey) IsActive(now time.Time) bool {
	if k.RetiredAt != nil {
		return false
	}
	if !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
		return false
	}
	return true
}

// IsExpired reports whether the key is past its NotAfter as of now (zero NotAfter never
// expires).
func (k SigningKey) IsExpired(now time.Time) bool {
	return !k.NotAfter.IsZero() && !now.Before(k.NotAfter)
}

// Keyset is the resolved signing material for a single tenant at a point in time: the active
// signer plus every key that may still verify a token (the active key and any retired-but-not-
// yet-expired keys). It is what tokens/jwt needs to sign and verify for that tenant.
type Keyset struct {
	// TenantID is the tenant this keyset belongs to.
	TenantID string
	// Active is the key that signs new tokens.
	Active SigningKey
	// Verify is every key that may verify a token, keyed by KeyID. It always includes Active.
	Verify map[string]SigningKey
}

// Store is the persistence half of the keystore contract (the Store side of the Service/Store
// split). It is the minimal capability interface a backend must implement; the Manager layers
// lifecycle and events on top. All methods are tenant-scoped and fail closed on a tenant
// mismatch. tenantID "" is the single-tenant partition.
//
// Backends store Secret in its KEK-encrypted form; the Manager handles seal/open, so a Store
// implementation never sees plaintext secrets beyond what NewManager hands it.
type Store interface {
	// CreateTenant records a new tenant with its initial signing key. It returns ErrTenantExists
	// if the tenant already exists (the Manager turns that into an idempotent no-op).
	CreateTenant(ctx context.Context, tenantID string, initial SigningKey) error

	// TenantExists reports whether the tenant has any key material.
	TenantExists(ctx context.Context, tenantID string) (bool, error)

	// PutSigningKey inserts or replaces a key for the tenant. It fails closed if key.TenantID is
	// set and differs from tenantID.
	PutSigningKey(ctx context.Context, tenantID string, key SigningKey) error

	// ActiveSigningKey returns the tenant's current active signer, or ErrNoActiveKey if none.
	ActiveSigningKey(ctx context.Context, tenantID string) (SigningKey, error)

	// VerificationKeys returns every key that may still verify a token for the tenant (active
	// plus retired-but-unexpired), keyed by KeyID.
	VerificationKeys(ctx context.Context, tenantID string) (map[string]SigningKey, error)

	// RotateSigningKey makes next the active signer and marks the current active key retired
	// (verify-only) with the given retiredAt. It is the persistence primitive behind renewal.
	RotateSigningKey(ctx context.Context, tenantID string, next SigningKey, retiredAt time.Time) error

	// RetireExpiredKeys deletes keys whose NotAfter is at or before now, returning the count
	// removed. It never touches the active key.
	RetireExpiredKeys(ctx context.Context, tenantID string, now time.Time) (int64, error)

	// RevokeTenantKeys immediately deletes every key for the tenant — the nuclear option, used
	// by delete and by emergency revocation. It does not touch other tenants.
	RevokeTenantKeys(ctx context.Context, tenantID string) error

	// DeleteTenant removes the tenant and all its key material. It is idempotent: deleting an
	// absent tenant is a no-op success.
	DeleteTenant(ctx context.Context, tenantID string) error
}

// TenantEraser erases a tenant's records from one downstream store (sessions, tokens, identity,
// …). DeleteTenant fans out across the registered erasers so a single auditable call purges all
// tenant-scoped state, not just crypto material. Implementations must be idempotent and safe to
// re-run (resumable delete).
type TenantEraser interface {
	// EraseTenant removes every record belonging to tenantID from this store. It must be a
	// no-op success when there is nothing to erase.
	EraseTenant(ctx context.Context, tenantID string) error
}

// TenantEraserFunc adapts a plain function to TenantEraser.
type TenantEraserFunc func(ctx context.Context, tenantID string) error

// EraseTenant calls f.
func (f TenantEraserFunc) EraseTenant(ctx context.Context, tenantID string) error {
	return f(ctx, tenantID)
}
