package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service defines the business logic for session management.
type Service interface {
	CreateSession(ctx context.Context, userID uuid.UUID, tenantID string, userAgent string, ip string, duration time.Duration) (*Session, string, error)
	ValidateSession(ctx context.Context, token string, opts ...Option) (*Session, error)

	// Touch slides a session's expiry to now+duration without changing its token, returning the
	// updated session. It is the idle-timeout primitive: call it on activity to keep an active
	// session alive. An unknown or already-expired session yields ErrSessionNotFound.
	Touch(ctx context.Context, token string, duration time.Duration, opts ...Option) (*Session, error)

	// Rotate issues a fresh token for the SAME logical session (same session ID and metadata),
	// invalidating the old token, and resets the lifetime to now+duration. It returns the updated
	// session and the new plaintext token. Call it after any privilege change — login over an
	// existing anonymous session, MFA/step-up, a role grant — to defeat session fixation: a token
	// an attacker may have fixed stops working the moment the victim authenticates. An unknown or
	// already-expired session yields ErrSessionNotFound.
	Rotate(ctx context.Context, token string, duration time.Duration, opts ...Option) (*Session, string, error)

	RevokeSession(ctx context.Context, token string, opts ...Option) error
}

type service struct {
	store Store
	now   func() time.Time
}

// NewService creates a new sessions Service. It panics on a nil store (never valid; fail fast at
// startup rather than with a nil-pointer panic deep in a request).
func NewService(store Store, opts ...ServiceOption) Service {
	if store == nil {
		panic("sessions: NewService requires a non-nil Store")
	}
	s := &service{
		store: store,
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// ServiceOption configures a sessions Service at construction time.
type ServiceOption func(*service)

// WithClock overrides the time source used for session creation, expiry checks, and slide
// (primarily for tests). A nil clock is ignored; NewService falls back to time.Now.
func WithClock(now func() time.Time) ServiceOption { return func(s *service) { s.now = now } }

// generateToken mints a fresh, high-entropy opaque session token.
func generateToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random session token: %w", err)
	}
	return hex.EncodeToString(tokenBytes), nil
}

func (s *service) CreateSession(ctx context.Context, userID uuid.UUID, tenantID string, userAgent string, ip string, duration time.Duration) (*Session, string, error) {
	token, err := generateToken()
	if err != nil {
		return nil, "", err
	}
	hash := s.hashToken(token)
	now := s.now()

	session := &Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		TokenHash: hash,
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
	}

	if err := s.store.CreateSession(ctx, session, WithTenant(tenantID)); err != nil {
		return nil, "", err
	}

	return session, token, nil
}

func (s *service) ValidateSession(ctx context.Context, token string, opts ...Option) (*Session, error) {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, hash, opts...)
	if err != nil {
		return nil, err
	}

	if s.now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// Touch slides a session's expiry without changing its token.
func (s *service) Touch(ctx context.Context, token string, duration time.Duration, opts ...Option) (*Session, error) {
	session, err := s.ValidateSession(ctx, token, opts...)
	if err != nil {
		return nil, err
	}
	currentHash := session.TokenHash // unchanged by Touch; the compare-and-set key
	session.ExpiresAt = s.now().Add(duration)
	if err := s.store.UpdateSession(ctx, session, currentHash, WithTenant(session.TenantID)); err != nil {
		return nil, err
	}
	return session, nil
}

// Rotate issues a new token for the same logical session, invalidating the old one.
func (s *service) Rotate(ctx context.Context, token string, duration time.Duration, opts ...Option) (*Session, string, error) {
	session, err := s.ValidateSession(ctx, token, opts...)
	if err != nil {
		return nil, "", err
	}

	newToken, err := generateToken()
	if err != nil {
		return nil, "", err
	}
	// Replace the stored token hash (the old plaintext token no longer hashes to a stored value,
	// so it stops validating) and reset the lifetime. The swap is a compare-and-set on the old
	// hash, so a concurrent rotation of the same token makes the loser observe ErrSessionNotFound
	// rather than receive a token that would never validate.
	oldHash := session.TokenHash
	session.TokenHash = s.hashToken(newToken)
	session.ExpiresAt = s.now().Add(duration)
	if err := s.store.UpdateSession(ctx, session, oldHash, WithTenant(session.TenantID)); err != nil {
		return nil, "", err
	}
	return session, newToken, nil
}

func (s *service) RevokeSession(ctx context.Context, token string, opts ...Option) error {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, hash, opts...)
	if err != nil {
		return err
	}

	return s.store.DeleteSession(ctx, session.ID, WithTenant(session.TenantID))
}

func (s *service) hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
