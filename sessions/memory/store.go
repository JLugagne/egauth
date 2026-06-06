// Package memory provides an in-memory sessions.Store, primarily for tests and
// single-process use.
//
// # Production requirement: periodic eviction is MANDATORY
//
// The Store grows without bound unless DeleteExpired is called periodically.
// Every expired session row remains in the in-memory map until explicitly
// purged; under load a production deployment that skips periodic eviction will
// exhaust available memory, creating a trivial denial-of-service vector.
//
// Use [github.com/JLugagne/egauth/janitor] to schedule eviction at startup:
//
//	store := memory.NewStore()
//	j := janitor.Start(ctx, 5*time.Minute, func() {
//	    store.DeleteExpired(context.Background(), tenantID)
//	})
//	defer j.Stop()
//
// This in-memory backend is suitable for tests and single-binary deployments
// where controlled restart bounds the total session count. For persistent or
// horizontally-scaled deployments, use the sessions/pgx backend instead.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/google/uuid"
)

// FindSessionByHash retrieves a session by its token hash, scoped to tenantID.
//
// Lookup is O(1) via the secondary byHash index. If the matched session is past its
// expiry it is opportunistically evicted from both maps and reported as not found, so
// the store does not retain stale rows on the hot path. Callers that still want a bulk
// purge can use DeleteExpired.
func (s *Store) FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.byHash[hashKey(tenantID, tokenHash)]
	if !ok {
		return nil, sessions.ErrSessionNotFound
	}

	sess, ok := s.sessions[id]
	if !ok || sess.TokenHash != tokenHash || sess.TenantID != tenantID {
		// Defensive: index points at a missing or mismatched row. Drop the stale key.
		delete(s.byHash, hashKey(tenantID, tokenHash))
		return nil, sessions.ErrSessionNotFound
	}

	// Opportunistic eviction of the looked-up key only (bounded, O(1)).
	if sess.ExpiresAt.Before(time.Now()) {
		delete(s.sessions, id)
		delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))
		return nil, sessions.ErrSessionNotFound
	}

	sCopy := *sess
	return &sCopy, nil
}

// Store is an in-memory implementation of sessions.Store.
type Store struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*sessions.Session
	// byHash is a secondary index mapping a tenant-scoped token-hash key to the owning
	// session ID, so FindSessionByHash is O(1) instead of scanning the whole map. It is
	// maintained in lockstep with sessions under the write lock by every mutator.
	byHash map[string]uuid.UUID
}

// NewStore creates a new in-memory sessions Store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[uuid.UUID]*sessions.Session),
		byHash:   make(map[string]uuid.UUID),
	}
}

// hashKey builds the secondary-index key. The token hash alone is not unique across
// tenants, so the key is scoped by tenant to preserve tenant isolation. The NUL
// separator cannot appear in a hex SHA-256 hash, so the key is unambiguous.
func hashKey(tenantID, tokenHash string) string {
	return tenantID + "\x00" + tokenHash
}

// CreateSession persists a new session. If the record carries a non-empty TenantID that
// differs from tenantID, it returns ErrTenantMismatch.
func (s *Store) CreateSession(ctx context.Context, tenantID string, session *sessions.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session.TenantID != "" && session.TenantID != tenantID {
		return sessions.ErrTenantMismatch
	}

	sCopy := *session
	sCopy.TenantID = tenantID

	s.sessions[sCopy.ID] = &sCopy
	s.byHash[hashKey(sCopy.TenantID, sCopy.TokenHash)] = sCopy.ID

	return nil
}

// UpdateSession updates the mutable fields of an existing session (token hash, expiry,
// user-agent, IP) identified by session.ID, as a compare-and-set on expectedTokenHash. The ID
// and tenant are immutable.
func (s *Store) UpdateSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.sessions[session.ID]
	if !ok || existing.TenantID != tenantID || existing.TokenHash != expectedTokenHash {
		// Unknown session, wrong tenant, or the token was already rotated away by a concurrent
		// request (the compare failed).
		return sessions.ErrSessionNotFound
	}

	sCopy := *session
	sCopy.TenantID = existing.TenantID // tenant is immutable
	s.sessions[session.ID] = &sCopy

	// Keep the hash index in lockstep with the rotation: the old hash key (equal to
	// expectedTokenHash, since the compare-and-set above succeeded) is removed and the
	// new hash is added. Both keys are tenant-scoped on the immutable tenant.
	if sCopy.TokenHash != existing.TokenHash {
		delete(s.byHash, hashKey(existing.TenantID, existing.TokenHash))
	}
	s.byHash[hashKey(sCopy.TenantID, sCopy.TokenHash)] = sCopy.ID
	return nil
}

// DeleteSession removes a session by its ID within the given tenant.
func (s *Store) DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.sessions[id]
	if !exists || sess.TenantID != tenantID {
		return sessions.ErrSessionNotFound
	}

	delete(s.sessions, id)
	delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))

	return nil
}

// DeleteExpired purges sessions past their expiry within the given tenant, returning the number deleted.
func (s *Store) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var deleted int64
	for id, sess := range s.sessions {
		if sess.TenantID != tenantID {
			continue
		}
		if sess.ExpiresAt.Before(now) {
			delete(s.sessions, id)
			delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))
			deleted++
		}
	}
	return deleted, nil
}

// DeleteSessionsByUserID removes all sessions for a user within the given tenant.
func (s *Store) DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.sessions {
		if sess.UserID == userID && sess.TenantID == tenantID {
			delete(s.sessions, id)
			delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))
		}
	}

	return nil
}

// Verify interface compliance.
var _ sessions.Store = (*Store)(nil)
