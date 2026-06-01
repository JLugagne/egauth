package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of sessions.Store.
type Store struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*sessions.Session
}

// NewStore creates a new in-memory sessions Store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[uuid.UUID]*sessions.Session),
	}
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

	return nil
}

// FindSessionByHash retrieves a session by its token hash, scoped to tenantID.
func (s *Store) FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash && sess.TenantID == tenantID {
			sCopy := *sess
			return &sCopy, nil
		}
	}

	return nil, sessions.ErrSessionNotFound
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
		}
	}

	return nil
}

// Verify interface compliance
var _ sessions.Store = (*Store)(nil)
