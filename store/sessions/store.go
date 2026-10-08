// Package sessions holds the contract of the stateful session store. Rows carry the sealed session
// attributes verbatim; the store never decodes them and keys every row by the SHA-256 digest of the
// session token.
package sessions

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

// RotateRequest moves the live row whose token digest is Previous to Next after a renewal. Next
// must keep the row's id, tenant, subject and lineage; the row's creation time is kept.
type RotateRequest struct {
	Previous []byte
	Next     Record
}

// ReplaceRequest revokes the live row whose id is Previous and inserts Next, a new row on the same
// lineage (password change, factor enrollment, reauthentication). Previous is the row id a resumed
// session's Handle carries, so a reissue needs no presented token. Next must have a new id and the
// tenant, subject and lineage of the replaced row.
type ReplaceRequest struct {
	Previous uuid.UUID
	Next     Record
}

// Revocation is one entry of the session revocation feed.
type Revocation struct {
	Tenant  principal.TenantID
	Session uuid.UUID
	At      time.Time
}

// Store persists stateful sessions. Every method is scoped to a tenant, through a TenantID, a
// Subject or a record. Lookups of a missing, expired or revoked row return store.ErrNotFound. Stores
// refuse a zero or invalid record with ErrInvalidRecord.
type Store interface {
	store.Base
	store.Reaper
	// Create inserts r. It returns store.ErrConflict when its id or token digest already exists.
	Create(ctx context.Context, r Record) error
	// Get returns the live row whose token digest is tokenHash.
	Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (Record, error)
	// Touch extends the idle expiry of the live row whose token digest is tokenHash to idleUntil,
	// clamped to its absolute expiry, and returns the stored idle expiry. It never shortens it. It
	// returns store.ErrNotFound once the row is gone, so a concurrent rotation is never undone.
	Touch(ctx context.Context, t principal.TenantID, tokenHash []byte, idleUntil time.Time) (time.Time, error)
	// Rotate applies req only while the row with digest req.Previous is live and has the id, tenant,
	// subject and lineage of req.Next; otherwise it changes nothing and returns store.ErrConflict.
	Rotate(ctx context.Context, req RotateRequest) error
	// Replace atomically revokes the row with id req.Previous, appends it to the revocation feed and
	// inserts req.Next, only while that row is live and has the tenant, subject and lineage of
	// req.Next under another id; otherwise it changes nothing and returns store.ErrConflict (C-33).
	Replace(ctx context.Context, req ReplaceRequest) error
	// Revoke ends the row whose token digest is tokenHash and appends it to the revocation feed. It is
	// idempotent.
	Revoke(ctx context.Context, t principal.TenantID, tokenHash []byte) error
	// RevokeSession ends the row id of s, the session a Handle or a SessionEnded event names, and
	// appends it to the revocation feed. A row of another subject or tenant is never touched. It is
	// idempotent.
	RevokeSession(ctx context.Context, s principal.Subject, id uuid.UUID) error
	// RevokeForSubject ends every row of s except those of exceptLineage (uuid.Nil keeps none) and
	// appends each to the revocation feed. It is idempotent.
	RevokeForSubject(ctx context.Context, s principal.Subject, exceptLineage uuid.UUID) error
	// RevocationsSince returns the revocations appended strictly after c, oldest first, and the
	// cursor to resume from. Positions are store-issued: a revocation stamped with an earlier
	// timestamp is still returned after c (C-18).
	RevocationsSince(ctx context.Context, c store.Cursor) ([]Revocation, store.Cursor, error)
	// DeleteForSubject erases every row of s, for account deletion.
	DeleteForSubject(ctx context.Context, s principal.Subject) error
}
