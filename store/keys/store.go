// Package keys holds the persistence contract of per-tenant signing keys. Stores keep the sealed
// private material as opaque bytes and never see a KEK.
package keys

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

const (
	// AADVersionLegacy marks key material sealed by v0.16, before associated data was mandatory.
	AADVersionLegacy uint8 = 0
	// AADVersionCurrent marks key material sealed under the v0.17 format.
	AADVersionCurrent uint8 = 1
)

var (
	// ErrNoActiveKey reports a tenant with keys but no active signer.
	ErrNoActiveKey = errors.New("keys: no active signing key")
	// ErrTenantTombstoned reports a tenant erased by EraseTenant or Tombstone; it can never be
	// provisioned again (T-13).
	ErrTenantTombstoned = errors.New("keys: tenant tombstoned")
	// ErrInvalidRotation reports a Rotation that is not Valid.
	ErrInvalidRotation = errors.New("keys: invalid rotation")
	// ErrLegacyAADVersion reports a key inserted with an AADVersion other than AADVersionCurrent: v0.16
	// material is only ever read and re-sealed, never written fresh, so startup never meets a new v0
	// row (C-58).
	ErrLegacyAADVersion = errors.New("keys: new key material must use AADVersionCurrent")
)

// Key is one sealed signing key of a tenant.
type Key struct {
	Tenant     principal.TenantID
	KeyID      string
	Alg        string
	Sealed     []byte
	AADVersion uint8
	CreatedAt  time.Time
	NotAfter   time.Time
	RetiredAt  *time.Time
}

// IsActive reports whether the key may sign at now: not retired and not past NotAfter.
func (k Key) IsActive(now time.Time) bool {
	return k.RetiredAt == nil && !k.IsExpired(now)
}

// IsExpired reports whether the key is past a non-zero NotAfter at now.
func (k Key) IsExpired(now time.Time) bool {
	return !k.NotAfter.IsZero() && !now.Before(k.NotAfter)
}

// Verifies reports whether the key may still verify a token at now. A retired key verifies only
// until a non-zero NotAfter, so a retired key without one never verifies (X-16).
func (k Key) Verifies(now time.Time) bool {
	if k.RetiredAt != nil && k.NotAfter.IsZero() {
		return false
	}
	return !k.IsExpired(now)
}

// Rotation makes Next the active signer and retires Previous, the key id of the signer the caller
// read, at RetiredAt. Naming Previous makes concurrent rotations safe: the loser gets
// store.ErrConflict instead of retiring the key the winner just activated. The retired key keeps
// verifying for the overlap only: its NotAfter becomes OverlapUntil, or stays at its own NotAfter
// when that is earlier. OverlapUntil has no zero "never" form; Expiry.OverlapUntil refuses a
// NeverExpire overlap, so a RenewKeysRequest.Overlap of NeverExpire is an error (X-16).
type Rotation struct {
	Previous     string
	Next         Key
	RetiredAt    time.Time
	OverlapUntil time.Time
}

// Valid reports whether r retires a named key in favour of a different one sealed under
// AADVersionCurrent and active at RetiredAt, with a non-zero overlap end not before RetiredAt.
func (r Rotation) Valid() bool {
	if r.Previous == "" || r.Next.KeyID == "" || r.Next.KeyID == r.Previous || r.Next.AADVersion != AADVersionCurrent {
		return false
	}
	if r.Next.RetiredAt != nil || r.RetiredAt.IsZero() || r.OverlapUntil.IsZero() {
		return false
	}
	return !r.OverlapUntil.Before(r.RetiredAt) && r.Next.IsActive(r.RetiredAt)
}

// Change is one entry of the key change feed: the tenant whose keyset changed.
type Change struct {
	Tenant principal.TenantID
}

// SealedRef addresses the sealed material of one key.
type SealedRef struct {
	Tenant principal.TenantID
	KeyID  string
}

// V016Row is a v0.16-sealed key awaiting upgrade.
type V016Row struct {
	Ref    SealedRef
	Sealed []byte
}

// Reseal is the compare-and-swap of sealed key material: Old is the exact sealed bytes that were
// read, so material replaced in the meantime is never overwritten.
type Reseal struct {
	Ref SealedRef
	Old []byte
	New []byte
}

// Store persists tenant keys. A key is addressed by its tenant, so every method takes one.
//
// Every method that inserts a key (CreateTenant, PutKey, Rotate) checks the tombstone in the same
// transaction as the insert and returns ErrTenantTombstoned for an erased tenant (T-13). Each one
// also returns ErrLegacyAADVersion for a key whose AADVersion is not AADVersionCurrent.
type Store interface {
	store.Base
	store.Reaper

	// CreateTenant records a tenant with its first key. It returns ErrLegacyAADVersion for a v0 key,
	// ErrTenantTombstoned for an erased tenant and store.ErrConflict when the tenant already has keys.
	CreateTenant(ctx context.Context, initial Key) error
	// TenantExists reports whether the tenant has any key.
	TenantExists(ctx context.Context, t principal.TenantID) (bool, error)
	// PutKey inserts a key. It returns ErrLegacyAADVersion for a v0 key, ErrTenantTombstoned for an
	// erased tenant and store.ErrConflict when the key id exists in the tenant: a key id is never
	// reused with other material.
	PutKey(ctx context.Context, k Key) error
	// ActiveKey returns the current signer, or ErrNoActiveKey.
	ActiveKey(ctx context.Context, t principal.TenantID) (Key, error)
	// VerificationKeys returns every key that may still verify a token: those for which Verifies
	// holds at store time.
	VerificationKeys(ctx context.Context, t principal.TenantID) ([]Key, error)
	// Rotate atomically inserts r.Next, retires r.Previous and caps its NotAfter as Rotation
	// describes. It returns ErrInvalidRotation when r is not Valid (a v0 r.Next included),
	// ErrTenantTombstoned for an erased tenant, and store.ErrConflict when r.Previous is not the
	// tenant's unretired signer, a concurrent rotation having won, or when r.Next's key id exists in
	// the tenant. On any error nothing changes.
	Rotate(ctx context.Context, r Rotation) error
	// RevokeTenantKeys deletes every key of the tenant at once. It is idempotent.
	RevokeTenantKeys(ctx context.Context, t principal.TenantID) error
	// Tombstone erases the tenant's keys and forbids its reprovisioning. It is idempotent.
	Tombstone(ctx context.Context, t principal.TenantID) error
	// IsTombstoned reports whether the tenant was tombstoned.
	IsTombstoned(ctx context.Context, t principal.TenantID) (bool, error)
	// ChangesSince returns the tenants whose keys changed after the cursor, and the cursor to resume
	// from. The cursor is store-issued, never a clock reading (T-15). Every keyset change appends to
	// the feed, deletions as much as insertions: CreateTenant, PutKey, Rotate, RevokeTenantKeys,
	// Tombstone, EraseTenant and the keys ReapExpired removes. Instances evict their verification
	// caches from this feed, so a missing deletion keeps a revoked key verifying elsewhere.
	ChangesSince(ctx context.Context, c store.Cursor) ([]Change, store.Cursor, error)

	// CountLegacySealed returns how many keys still have aad_version 0.
	CountLegacySealed(ctx context.Context) (int64, error)
	// V016Sealed returns up to limit aad_version 0 keys after the cursor, with the cursor of the
	// last one. The zero cursor starts from the beginning. DESIGN section 4.7 calls it
	// LegacySealed(cursor).
	V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]V016Row, store.Cursor, error)
	// ReplaceSealed stores r.New and sets aad_version to AADVersionCurrent only while the stored
	// sealed bytes still equal r.Old, and reports whether it did. It serves both the v0.16 upgrade
	// and the lazy re-seal after a KEK rotation, and changes no other field of the key.
	ReplaceSealed(ctx context.Context, r Reseal) (bool, error)
}
