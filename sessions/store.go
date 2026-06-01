package sessions

import (
	"context"

	"github.com/google/uuid"
)

// Store defines the persistence interface for Sessions.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty
// string is a legal tenant key (the single-tenant default partition); it must still be
// passed explicitly.
type Store interface {
	// CreateSession persists a new session. If the record already carries a non-empty
	// TenantID that differs from tenantID, it returns ErrTenantMismatch.
	CreateSession(ctx context.Context, tenantID string, session *Session) error

	// FindSessionByHash retrieves a session by its token hash, scoped to tenantID.
	FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*Session, error)

	// UpdateSession updates a mutable session (its token hash, expiry, and last-seen
	// user-agent/IP) identified by session.ID. It is a compare-and-set on the token: the update
	// applies only if the stored token hash still equals expectedTokenHash, otherwise it returns
	// ErrSessionNotFound (also returned for an unknown id/tenant). This makes the service's Rotate
	// safe under concurrency — two requests racing to rotate the same token: the first swaps the
	// hash, the second's compare fails and it gets an honest ErrSessionNotFound rather than a
	// fresh token that would never validate. The session ID and tenant are immutable.
	UpdateSession(ctx context.Context, tenantID string, session *Session, expectedTokenHash string) error

	// DeleteSession removes a session by its ID within the given tenant.
	DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error

	// DeleteSessionsByUserID removes all sessions for a user within the given tenant.
	DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error

	// DeleteExpired purges sessions past their expiry within the given tenant, returning the
	// number deleted. It is the schedulable GC reaper that keeps the session store from growing
	// unbounded. Run it periodically from a background job.
	DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}
