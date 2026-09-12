package tokens

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JLugagne/egauth/revocation"
	"github.com/google/uuid"
)

// AccessTokenRevocationChecker decides whether an already-issued access token must be treated
// as revoked. It is consulted by RequireAuth / ContextMiddleware AFTER the token's signature
// and expiry have been verified and BEFORE any route gate or protected handler, so an account
// revocation can invalidate an access JWT without waiting for its AccessTTL to elapse.
//
// The checker receives the verified tenant, subject and issue time rather than the full claims
// so it stays independent of the custom claims type. A non-nil error fails the request closed
// (401): a revocation lookup that cannot be answered must not be treated as "not revoked".
//
// RequireAuth performs NO lookup when no checker is configured, preserving the stateless,
// database-free verification path.
type AccessTokenRevocationChecker interface {
	IsAccessTokenRevoked(ctx context.Context, tenantID string, userID uuid.UUID, issuedAt time.Time) (bool, error)
}

// AccessTokenRevocationCheckerFunc adapts a plain function to AccessTokenRevocationChecker.
type AccessTokenRevocationCheckerFunc func(ctx context.Context, tenantID string, userID uuid.UUID, issuedAt time.Time) (bool, error)

// IsAccessTokenRevoked implements AccessTokenRevocationChecker.
func (f AccessTokenRevocationCheckerFunc) IsAccessTokenRevoked(ctx context.Context, tenantID string, userID uuid.UUID, issuedAt time.Time) (bool, error) {
	return f(ctx, tenantID, userID, issuedAt)
}

// WithAccessTokenRevocation wires an access-token revocation checker into RequireAuth /
// ContextMiddleware. When configured, every verified access token is checked; a revoked token
// (or a checker error) is rejected with 401 even though its signature and expiry are valid.
//
// This closes the logout/revocation window: without it, an access JWT minted before a logout,
// password change, account disable or "log out everywhere" stays accepted until AccessTTL
// (commonly 15 minutes). With a checker backed by the revocation bus (see
// NewRevocationTracker), a single revocation event can invalidate the refresh family AND reject
// the already-issued access tokens.
//
// The option is opt-in: when it is not configured there is no added per-request store lookup
// and the residual AccessTTL window applies. Pass nil to disable.
func WithAccessTokenRevocation[C any](checker AccessTokenRevocationChecker) AuthOption[C] {
	return func(a *authConfig[C]) { a.accessTokenRevocation = checker }
}

// accessTokenRevoked reports whether claims belong to a token the configured checker rejects.
// It fails closed: a checker error is treated as revoked. It is a no-op when no checker is set.
func (cfg *authConfig[C]) accessTokenRevoked(ctx context.Context, claims *Claims[C]) bool {
	if cfg.accessTokenRevocation == nil {
		return false
	}
	revoked, err := cfg.accessTokenRevocation.IsAccessTokenRevoked(ctx, claims.TenantID, claims.Subject, claims.IssuedAt)
	return err != nil || revoked
}

// accountKey scopes a revocation cutoff to one (tenant, user) pair.
type accountKey struct {
	tenantID string
	userID   uuid.UUID
}

// RevocationTracker is an in-memory AccessTokenRevocationChecker that tracks per-account
// access-token cutoff times from a revocation.Bus. Subscribe it by constructing it with the
// bus: NewRevocationTracker(bus) registers the tracker for account-scoped (TargetUser)
// revocations. Any access token issued at or before the latest cutoff for its (tenant, user)
// is reported revoked.
//
// The tracker holds only the maximum cutoff time per account, so publishing multiple
// revocations is idempotent and cheap. State is in-process and non-durable: after a restart the
// tracker is empty until the next revocation event, so a token that should have been rejected
// is accepted for at most AccessTTL again. Persisting cutoffs (or seeding the tracker at
// startup) is left to the consumer.
type RevocationTracker struct {
	mu     sync.RWMutex
	cutoff map[accountKey]time.Time
}

// NewRevocationTracker returns a tracker subscribed to bus for account-scoped revocations. A
// nil bus yields a tracker that never revokes (useful in tests and single-process opt-outs).
func NewRevocationTracker(bus revocation.Bus) *RevocationTracker {
	t := &RevocationTracker{cutoff: make(map[accountKey]time.Time)}
	if bus != nil {
		bus.Subscribe(revocation.TargetUser, t)
	}
	return t
}

// HandleRevocation implements revocation.Handler. It records the cutoff for account-scoped
// revocations and ignores every other target type. A missing CutoffTime is stamped with the
// current time so an event that does not carry one still invalidates existing tokens.
func (t *RevocationTracker) HandleRevocation(_ context.Context, rev revocation.Revocation) error {
	if rev.TargetType != revocation.TargetUser {
		return nil
	}
	userID, err := uuid.Parse(rev.TargetID)
	if err != nil {
		return fmt.Errorf("tokens: access-token revocation: invalid user id %q: %w", rev.TargetID, err)
	}
	cutoff := rev.CutoffTime
	if cutoff.IsZero() {
		cutoff = time.Now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	key := accountKey{tenantID: rev.TenantID, userID: userID}
	if cutoff.After(t.cutoff[key]) {
		t.cutoff[key] = cutoff
	}
	return nil
}

// IsAccessTokenRevoked implements AccessTokenRevocationChecker. It never errors.
func (t *RevocationTracker) IsAccessTokenRevoked(_ context.Context, tenantID string, userID uuid.UUID, issuedAt time.Time) (bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	cutoff, ok := t.cutoff[accountKey{tenantID: tenantID, userID: userID}]
	if !ok {
		return false, nil
	}
	return !issuedAt.After(cutoff), nil
}
