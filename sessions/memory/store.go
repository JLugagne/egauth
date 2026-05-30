package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/libauth/sessions"
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

// CreateSession persists a new session.
func (s *Store) CreateSession(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sCopy := *session

	opt := sessions.ApplyOptions(opts)
	if opt.TenantID != nil {
		sCopy.TenantID = *opt.TenantID
	}

	s.sessions[sCopy.ID] = &sCopy

	return nil
}

// FindSessionByHash retrieves a session by its token hash.
func (s *Store) FindSessionByHash(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := sessions.ApplyOptions(opts)

	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			if opt.TenantID == nil || sess.TenantID == *opt.TenantID {
				sCopy := *sess
				return &sCopy, nil
			}
		}
	}

	return nil, sessions.ErrSessionNotFound
}

// UpdateSession updates the mutable fields of an existing session (token hash, expiry,
// user-agent, IP) identified by session.ID, as a compare-and-set on expectedTokenHash. The ID
// and tenant are immutable.
func (s *Store) UpdateSession(ctx context.Context, session *sessions.Session, expectedTokenHash string, opts ...sessions.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := sessions.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

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

// DeleteSession removes a session by its ID.
func (s *Store) DeleteSession(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := sessions.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	sess, exists := s.sessions[id]
	if !exists || sess.TenantID != tenantID {
		return sessions.ErrSessionNotFound
	}

	delete(s.sessions, id)

	return nil
}

// DeleteExpired purges sessions past their expiry, returning the number deleted. With WithTenant
// it sweeps a single tenant, otherwise all.
func (s *Store) DeleteExpired(ctx context.Context, opts ...sessions.Option) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := sessions.ApplyOptions(opts)
	now := time.Now()
	var deleted int64
	for id, sess := range s.sessions {
		if opt.TenantID != nil && sess.TenantID != *opt.TenantID {
			continue
		}
		if sess.ExpiresAt.Before(now) {
			delete(s.sessions, id)
			deleted++
		}
	}
	return deleted, nil
}

// DeleteSessionsByUserID removes all sessions for a user.
func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := sessions.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	for id, sess := range s.sessions {
		if sess.UserID == userID && sess.TenantID == tenantID {
			delete(s.sessions, id)
		}
	}

	return nil
}

// Verify interface compliance
var _ sessions.Store = (*Store)(nil)
