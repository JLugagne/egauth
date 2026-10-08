// Package tokens holds the contract of the refresh-family and API-key store. Refresh records carry
// the sealed session attributes verbatim; the store never decodes them and keys every record by the
// SHA-256 digest of its handle.
package tokens

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

// ReuseGrace is how long after a refresh token was consumed the same client may present it again
// without the family being revoked (two tabs racing one rotation). It is measured with the store's
// clock against the persisted consumed_at, never with an application clock (T-21).
const ReuseGrace = 10 * time.Second

// RotationRequest consumes the refresh token whose digest is Presented and issues Next in its
// place; ConsumeForRotation refuses a Next that leaves the consumed token's tenant, subject, lineage
// or family. Next's ClientFingerprint is persisted as the consumed token's consumed_by.
type RotationRequest struct {
	Presented []byte
	Next      RefreshRecord
}

// Rotation reports a successful rotation: the family it happened in and when the store consumed
// the presented token, in store time.
type Rotation struct {
	Family     uuid.UUID
	ConsumedAt time.Time
}

// ReissueRequest revokes the live family Family and starts Next, a new family continuing its
// lineage (password change, factor enrollment, reauthentication); Reissue refuses a Next that
// leaves Family's tenant, subject or lineage. Family is the id a session.Handle carries.
type ReissueRequest struct {
	Family uuid.UUID
	Next   RefreshRecord
}

// FamilyState is what the revocation cache needs to decide whether an access token's sid is live.
type FamilyState struct {
	Subject   principal.Subject
	Lineage   uuid.UUID
	Revoked   bool
	ExpiresAt time.Time
}

// Live reports whether the family is neither revoked nor past its absolute expiry at now.
func (f FamilyState) Live(now time.Time) bool { return !f.Revoked && now.Before(f.ExpiresAt) }

// Revocation is one entry of the family revocation feed.
type Revocation struct {
	Tenant principal.TenantID
	Family uuid.UUID
	At     time.Time
}

// Store persists refresh families and API keys. Every method is scoped to a tenant, through a
// TenantID, a Subject or a record. Lookups of a missing, expired or erased record return
// store.ErrNotFound. Stores refuse a zero or invalid record with ErrInvalidRecord.
type Store interface {
	store.Base
	store.Reaper
	// Create starts a new family with its first token. It returns store.ErrConflict when the token
	// or the family already exists.
	Create(ctx context.Context, r RefreshRecord) error
	// Get returns the token with digest tokenHash, consumed or not. It returns ErrRevoked for a
	// token whose family is revoked or past its absolute expiry.
	Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (RefreshRecord, error)
	// ConsumeForRotation atomically consumes the presented token and inserts req.Next. When the token
	// was already consumed, the store decides with its own clock and the persisted consumed_by: within
	// ReuseGrace and from the same non-empty fingerprint it returns ErrConcurrent and changes
	// nothing; otherwise it revokes the family, appends to the revocation feed and returns ErrReused.
	// It returns ErrRevoked for a revoked or expired family, store.ErrNotFound for an unknown or
	// idle-expired token, and store.ErrConflict when req.Next does not continue the presented token's
	// tenant, subject, lineage and family.
	ConsumeForRotation(ctx context.Context, req RotationRequest) (Rotation, error)
	// Reissue atomically revokes req.Family and inserts req.Next, only while req.Family is live and
	// has the tenant, subject and lineage of req.Next; otherwise it changes nothing and returns
	// store.ErrConflict (C-33).
	Reissue(ctx context.Context, req ReissueRequest) error
	// FamilyState returns the state of family, store.ErrNotFound when it never existed or was reaped.
	FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (FamilyState, error)
	// RevokeFamily revokes family and appends it to the revocation feed. It is idempotent.
	RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error
	// RevokeForSubject revokes every family of s except those of exceptLineage (uuid.Nil keeps
	// none) and appends each to the revocation feed. It is idempotent.
	RevokeForSubject(ctx context.Context, s principal.Subject, exceptLineage uuid.UUID) error
	// RevocationsSince returns the revocations appended strictly after c, oldest first, and the
	// cursor to resume from. Positions are store-issued: a revocation stamped with an earlier
	// timestamp is still returned after c (C-18).
	RevocationsSince(ctx context.Context, c store.Cursor) ([]Revocation, store.Cursor, error)
	// DeleteForSubject erases every family and API key of s, for account deletion.
	DeleteForSubject(ctx context.Context, s principal.Subject) error
	// CreateAPIKey persists k after k.Validate. It returns store.ErrConflict for a duplicate id or
	// key hash.
	CreateAPIKey(ctx context.Context, k APIKey) error
	// GetAPIKey returns the key with digest keyHash, revoked or not; expired keys are not found.
	GetAPIKey(ctx context.Context, t principal.TenantID, keyHash []byte) (APIKey, error)
	// ListAPIKeys returns every key of owner, revoked ones included.
	ListAPIKeys(ctx context.Context, owner principal.Subject) ([]APIKey, error)
	// RevokeAPIKey soft-revokes the key id of owner. It returns store.ErrNotFound when owner has no
	// such key and is idempotent otherwise.
	RevokeAPIKey(ctx context.Context, owner principal.Subject, id uuid.UUID) error
}
