package sessions

import (
	"context"

	"github.com/google/uuid"
)

// Store defines the persistence interface for Sessions.
//
// It is the composition of the stable-core SessionStore (the create/lookup/mutate/delete
// operations the Service touches on every request path) and the optional SessionReaper (the
// schedulable expired-session sweep that only a background job calls). Segmenting the contract
// this way means a future v1.x capability can ship as a NEW optional interface — implementers
// type-assert for it — rather than as a new method on this interface, which would break every
// external Store. Both the in-memory and pgx stores implement the whole Store.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	SessionStore
	SessionReaper
}

// SessionStore is the stable-core capability of a sessions backend: the create, lookup, mutate
// and delete operations the Service needs on every request path. It is the part of the contract
// frozen for v1; new optional behaviour is added as a separate capability interface, never as a
// method here.
type SessionStore interface {
	// CreateSession persists a new session. If the record already carries a non-empty
	// TenantID that differs from tenantID, it returns ErrTenantMismatch.
	CreateSession(ctx context.Context, tenantID string, session *Session) error

	// FindSessionByHash retrieves a non-expired session by its token hash, scoped to tenantID.
	// Expired sessions are treated as not found: a record whose ExpiresAt is in the past must
	// yield ErrSessionNotFound, never the stale row. This is part of the contract every backend
	// must honour (the memory store evicts the expired match opportunistically; SQL backends add
	// an expires_at >= now() predicate) so that direct callers such as service.RevokeSession see
	// identical behaviour on every Store implementation.
	FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*Session, error)

	// UpdateSession updates a mutable session (its token hash, expiry, and last-seen
	// user-agent/IP) identified by session.ID. It is a compare-and-set on the token: the update
	// applies only if the stored token hash still equals expectedTokenHash, otherwise it returns
	// ErrSessionNotFound (also returned for an unknown id/tenant). This makes the service's Rotate
	// safe under concurrency — two requests racing to rotate the same token: the first swaps the
	// hash, the second's compare fails and it gets an honest ErrSessionNotFound rather than a
	// fresh token that would never validate.
	//
	// The session ID, tenant, UserID and CreatedAt are immutable: only TokenHash, ExpiresAt,
	// UserAgent and IP are copied onto the stored record. Any change to UserID or CreatedAt in
	// the passed session is ignored — re-binding a session to a different user is the job of
	// BindSession, not UpdateSession. Pinning CreatedAt also keeps the absolute-lifetime cap
	// (WithMaxLifetime) honest: a caller cannot extend a session past its cap by resetting it.
	UpdateSession(ctx context.Context, tenantID string, session *Session, expectedTokenHash string) error

	// BindSession atomically re-binds a session to a new UserID while rotating its token,
	// identified by session.ID and gated by a compare-and-set on expectedTokenHash (same
	// concurrency contract as UpdateSession: a stale expected hash yields ErrSessionNotFound).
	// It is the anonymous-to-authenticated upgrade primitive: a pre-auth session can be promoted
	// to an authenticated one without minting a new session row, defeating session fixation while
	// preserving the logical session ID. It copies UserID, TokenHash, ExpiresAt, UserAgent and IP
	// onto the stored record; the session ID, tenant and CreatedAt remain immutable. An unknown
	// id/tenant or a failed compare yields ErrSessionNotFound.
	BindSession(ctx context.Context, tenantID string, session *Session, expectedTokenHash string) error

	// DeleteSession removes a session by its ID within the given tenant.
	DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error

	// DeleteSessionsByUserID removes all sessions for a user within the given tenant.
	DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// SessionReaper is the optional GC capability of a sessions backend: the schedulable sweep that
// purges expired sessions. It is separated from the core SessionStore because the request path
// never calls it — only a background job (e.g. janitor.Start) does. The full Store composes
// SessionStore + SessionReaper; both the in-memory and pgx stores implement the whole Store.
type SessionReaper interface {
	// DeleteExpired purges sessions past their expiry within the given tenant, returning the
	// number deleted. It is the schedulable GC reaper that keeps the session store from growing
	// unbounded. Run it periodically from a background job.
	DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
