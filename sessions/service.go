package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/google/uuid"
)

// Service defines the business logic for session management.
type Service interface {
	CreateSession(ctx context.Context, tenantID string, userID uuid.UUID, userAgent string, ip string, duration time.Duration) (*Session, string, error)
	ValidateSession(ctx context.Context, tenantID string, token string) (*Session, error)
	// Touch slides a session's expiry to now+duration without changing its token, returning the
	// updated session. It is the idle-timeout primitive: call it on activity to keep an active
	// session alive. An unknown or already-expired session yields ErrSessionNotFound.
	Touch(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, error)
	// Rotate issues a fresh token for the SAME logical session (same session ID and metadata),
	// invalidating the old token, and resets the lifetime to now+duration. It returns the updated
	// session and the new plaintext token. Call it after any privilege change — login over an
	// existing anonymous session, MFA/step-up, a role grant — to defeat session fixation: a token
	// an attacker may have fixed stops working the moment the victim authenticates. An unknown or
	// already-expired session yields ErrSessionNotFound.
	Rotate(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, string, error)
	RevokeSession(ctx context.Context, tenantID string, token string) error
	// RevokeAllForUser deletes every session belonging to userID within tenantID — the
	// "log out everywhere" primitive. Call it after a password reset or account compromise to
	// kill an attacker's other live sessions, not just the current token. It is idempotent: a
	// user with no sessions yields no error.
	RevokeAllForUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}

type service struct {
	store       Store
	now         func() time.Time
	maxLifetime time.Duration
	events      event.Sink
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

func (s *service) CreateSession(ctx context.Context, tenantID string, userID uuid.UUID, userAgent string, ip string, duration time.Duration) (*Session, string, error) {
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

	if err := s.store.CreateSession(ctx, tenantID, session); err != nil {
		return nil, "", err
	}

	return session, token, nil
}

func (s *service) ValidateSession(ctx context.Context, tenantID string, token string) (*Session, error) {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, tenantID, hash)
	if err != nil {
		return nil, err
	}

	now := s.now()
	if now.After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	// Absolute lifetime cap: once a session is older than maxLifetime it is rejected even if it
	// has been kept warm within the idle window. Returns the same opaque ErrSessionNotFound as an
	// ordinary expiry so a caller cannot distinguish idle expiry from absolute-cap expiry.
	if deadline, ok := s.absoluteDeadline(session); ok && now.After(deadline) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// Touch slides a session's expiry without changing its token.
func (s *service) Touch(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, error) {
	session, err := s.ValidateSession(ctx, tenantID, token)
	if err != nil {
		return nil, err
	}
	currentHash := session.TokenHash // unchanged by Touch; the compare-and-set key
	// Clamp the slide so it can never push ExpiresAt past the absolute deadline (SEC-08).
	session.ExpiresAt = s.clampExpiry(session, s.now().Add(duration))
	if err := s.store.UpdateSession(ctx, tenantID, session, currentHash); err != nil {
		return nil, err
	}
	return session, nil
}

// Rotate issues a new token for the same logical session, invalidating the old one.
func (s *service) Rotate(ctx context.Context, tenantID string, token string, duration time.Duration) (*Session, string, error) {
	session, err := s.ValidateSession(ctx, tenantID, token)
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
	// Clamp the reset lifetime so it can never push ExpiresAt past the absolute deadline (SEC-08).
	session.ExpiresAt = s.clampExpiry(session, s.now().Add(duration))
	if err := s.store.UpdateSession(ctx, tenantID, session, oldHash); err != nil {
		return nil, "", err
	}
	return session, newToken, nil
}

func (s *service) RevokeSession(ctx context.Context, tenantID string, token string) error {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, tenantID, hash)
	if err != nil {
		return err
	}

	if err := s.store.DeleteSession(ctx, tenantID, session.ID); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.Logout, UserID: session.UserID.String(), TenantID: tenantID})
	return nil
}

func (s *service) hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// WithMaxLifetime sets an absolute cap on a session's lifetime, measured from its CreatedAt.
// Once now is past CreatedAt+d the session stops validating and can no longer be touched or
// rotated, regardless of how recently it was active — an idle-timeout slide can never keep a
// stolen-but-kept-warm token alive indefinitely. Touch and Rotate additionally clamp the new
// ExpiresAt so it never slides past the absolute deadline. The zero value disables the cap
// (idle timeout only), preserving the previous behaviour.
func WithMaxLifetime(d time.Duration) ServiceOption {
	return func(s *service) { s.maxLifetime = d }
}

// absoluteDeadline returns the absolute expiry deadline (CreatedAt+maxLifetime) for a session
// and whether an absolute cap is configured. When maxLifetime is zero the cap is disabled and
// ok is false.
func (s *service) absoluteDeadline(session *Session) (time.Time, bool) {
	if s.maxLifetime <= 0 {
		return time.Time{}, false
	}
	return session.CreatedAt.Add(s.maxLifetime), true
}

// clampExpiry returns the effective expiry for a session whose lifetime is being extended to
// candidate. When an absolute cap is configured it is min(candidate, CreatedAt+maxLifetime), so
// a slide can never push ExpiresAt past the absolute deadline. With no cap it returns candidate.
func (s *service) clampExpiry(session *Session, candidate time.Time) time.Time {
	if deadline, ok := s.absoluteDeadline(session); ok && candidate.After(deadline) {
		return deadline
	}
	return candidate
}

// RevokeAllForUser deletes every session belonging to userID within tenantID by forwarding to
// the store's DeleteSessionsByUserID. It is the "log out everywhere" primitive.
func (s *service) RevokeAllForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if err := s.store.DeleteSessionsByUserID(ctx, tenantID, userID); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.Logout, UserID: userID.String(), TenantID: tenantID, Reason: "all_sessions"})
	return nil
}

// WithEventSink registers a security-event sink (see the event package) that receives a Logout
// event whenever a session is revoked — RevokeSession (single sign-out) and RevokeAllForUser
// ("log out everywhere"). Optional; without it no events are emitted.
func WithEventSink(sink event.Sink) ServiceOption { return func(s *service) { s.events = sink } }

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *service) emit(ctx context.Context, e event.Event) { event.Emit(ctx, s.events, e) }
