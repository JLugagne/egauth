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
	strict   bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (sessions.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid
// default single-tenant partition. The "effective" tenant is the one from WithTenant, or, for
// CreateSession, the tenant carried on the session itself; strict mode rejects only when that
// effective tenant is empty. (DeleteExpired is exempt: it is a maintenance sweep that
// intentionally spans all tenants when no tenant is given.)
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new in-memory sessions Store.
func NewStore(opts ...Option) *Store {
	s := &Store{
		sessions: make(map[uuid.UUID]*sessions.Session),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant resolves the operation tenant (WithTenant takes precedence over fallback, the
// tenant carried on the record) and enforces ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(fallback string, opts []sessions.Option) (string, error) {
	o := sessions.ApplyOptions(opts)
	tenant := fallback
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", sessions.ErrTenantRequired
	}
	return tenant, nil
}

// CreateSession persists a new session.
func (s *Store) CreateSession(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, err := s.resolveTenant(session.TenantID, opts)
	if err != nil {
		return err
	}

	sCopy := *session
	sCopy.TenantID = tenant

	s.sessions[sCopy.ID] = &sCopy

	return nil
}

// FindSessionByHash retrieves a session by its token hash.
func (s *Store) FindSessionByHash(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := sessions.ApplyOptions(opts)
	// A nil tenant means "match any tenant" (no scoping). Strict mode forbids that unscoped
	// lookup, and an explicit empty tenant, so a forgotten WithTenant fails loudly.
	if s.strict && (opt.TenantID == nil || *opt.TenantID == "") {
		return nil, sessions.ErrTenantRequired
	}

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

	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
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

	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
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

	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
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
