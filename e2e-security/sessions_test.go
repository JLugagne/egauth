package e2esecurity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/janitor"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashToken replicates the internal hashing algorithm to query store directly.
func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// SEC-SES-01 (CVSS 7.5): Prevent eviction of active live sessions in sessions/memory.BoundedStore.
// When BoundedStore reaches capacity and no expired sessions exist, it must NOT evict active live sessions.
// Instead, session creation must fail with ErrStoreCapacityExceeded, keeping legitimate active users logged in.
func TestSecSes01_BoundedStoreEvictsActiveLiveSessions(t *testing.T) {
	ctx := context.Background()
	const cap = 2
	store := memory.NewBoundedStore(cap)
	now := time.Now()

	// 1. Create two legitimate active sessions with future expiration.
	// Session 1 expires in 1 hour.
	tokenHash1 := hashToken("token-victim-1")
	sess1 := &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  "tenant-1",
		UserID:    uuid.Must(uuid.NewV7()),
		TokenHash: tokenHash1,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateSession(ctx, "tenant-1", sess1))

	// Session 2 expires in 2 hours.
	tokenHash2 := hashToken("token-victim-2")
	sess2 := &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  "tenant-1",
		UserID:    uuid.Must(uuid.NewV7()),
		TokenHash: tokenHash2,
		ExpiresAt: now.Add(2 * time.Hour),
		CreatedAt: now,
	}
	require.NoError(t, store.CreateSession(ctx, "tenant-1", sess2))

	assert.Equal(t, cap, store.Len(), "Store capacity is reached")

	// 2. An attacker floods session creations (e.g. anonymous sessions or login requests).
	// Session 3 expires in 3 hours.
	tokenHash3 := hashToken("token-attacker-3")
	sess3 := &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  "tenant-1",
		UserID:    uuid.Must(uuid.NewV7()),
		TokenHash: tokenHash3,
		ExpiresAt: now.Add(3 * time.Hour),
		CreatedAt: now,
	}
	err := store.CreateSession(ctx, "tenant-1", sess3)
	require.ErrorIs(t, err, sessions.ErrStoreCapacityExceeded,
		"SEC-SES-01 fixed: CreateSession must return ErrStoreCapacityExceeded when store is full of live sessions")

	// 3. Confirm secure behavior: Store remains capped at 2, and existing active sessions remain valid and untouched.
	assert.Equal(t, cap, store.Len())

	found1, err := store.FindSessionByHash(ctx, "tenant-1", tokenHash1)
	require.NoError(t, err, "Active, non-expired Session 1 must NOT be evicted")
	assert.Equal(t, sess1.ID, found1.ID)

	found2, err := store.FindSessionByHash(ctx, "tenant-1", tokenHash2)
	require.NoError(t, err, "Active, non-expired Session 2 must NOT be evicted")
	assert.Equal(t, sess2.ID, found2.ID)

	// Attacker's Session 3 was not created in the store.
	_, err = store.FindSessionByHash(ctx, "tenant-1", tokenHash3)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound, "Session 3 was rejected and must not be found in the store")
}

// SEC-SES-06 (CVSS 5.4): Session expiry clamping by maxLifetime in CreateSession to prevent zombie retention.
// CreateSession clamps session.ExpiresAt by maxLifetime so stored sessions do not have ExpiresAt
// exceeding maxLifetime. When maxLifetime elapses, DeleteExpired successfully purges the expired
// session from the store, preventing uncollectable zombie sessions.
func TestSecSes06_CreateSessionBypassesMaxLifetime_ZombieRetention(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()

	// Virtual clock frozen at T0 in the past so real time.Now() (used by memory.Store.DeleteExpired)
	// has already passed maxLifetime.
	frozen := time.Now().Add(-2 * time.Hour)
	clockNow := frozen
	clock := func() time.Time { return clockNow }

	// Max lifetime is configured to 1 hour (SEC-08 cap).
	maxLifetime := 1 * time.Hour
	svc := sessions.NewService(store, sessions.WithClock(clock), sessions.WithMaxLifetime(maxLifetime))

	tenantID := "tenant-sec06"
	userID := uuid.Must(uuid.NewV7())

	// A session is created with duration = 10 hours ("remember-me" session).
	longDuration := 10 * time.Hour
	sess, token, err := svc.CreateSession(ctx, tenantID, userID, "UA", "127.0.0.1", longDuration)
	require.NoError(t, err)

	// Fixed behavior: session.ExpiresAt is clamped to CreatedAt + maxLifetime.
	assert.Equal(t, sess.CreatedAt.Add(maxLifetime), sess.ExpiresAt,
		"SEC-SES-06 fixed: CreateSession clamps initial ExpiresAt to CreatedAt+maxLifetime")

	// DeleteExpired purges the expired session because ExpiresAt was clamped.
	deleted, err := store.DeleteExpired(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted,
		"SEC-SES-06 fixed: DeleteExpired successfully purges the expired session")

	// The session record is no longer retained in the store.
	hash := hashToken(token)
	_, err = store.FindSessionByHash(ctx, tenantID, hash)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"Expired session is no longer retained in the store")

	// ValidateSession also rejects the session.
	clockNow = frozen.Add(2 * time.Hour)
	_, err = svc.ValidateSession(ctx, tenantID, token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"ValidateSession rejects session past maxLifetime")
}

// SEC-SES-09 (CVSS 4.0): CPU-intensive busy loop (Busy Loop) in janitor.Start with non-positive interval.
// Calling Start with non-positive interval must not result in a high-frequency busy loop;
// it should default to a safe minimum duration (e.g. 1 minute).
func TestSecSes09_JanitorBusyLoopOnNonPositiveInterval(t *testing.T) {
	var executions atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Calling Start with interval <= 0 triggers the safe fallback duration.
	j := janitor.Start(ctx, 0, func() {
		executions.Add(1)
	})
	defer j.Stop()

	// Wait 100ms — with a safe fallback interval, the callback must not execute in a high-frequency busy loop.
	time.Sleep(100 * time.Millisecond)
	j.Stop()

	count := executions.Load()
	assert.LessOrEqual(t, count, int64(1),
		"SEC-SES-09 fixed: interval <= 0 must not result in a high-frequency busy loop")
}

// SEC-SES-14 (CVSS 4.2): Prevent arbitrary user identity reassignment in sessions.Service.BindUser.
// BindUser must reject attempts to rebind an already-authenticated session (session.UserID != uuid.Nil)
// with ErrSessionAlreadyBound, preventing arbitrary session identity reassignment.
func TestSecSes14_BindUserOverwritesAuthenticatedUser(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := sessions.NewService(store)

	tenantID := "tenant-sec14"
	userA := uuid.Must(uuid.NewV7())
	userB := uuid.Must(uuid.NewV7())

	// 1. Create an active session already bound to User A.
	sessA, tokenA, err := svc.CreateSession(ctx, tenantID, userA, "UA", "127.0.0.1", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, userA, sessA.UserID)

	// 2. Call BindUser with User B on User A's session.
	// Fixed behavior: BindUser rejects rebinding an already-authenticated session with ErrSessionAlreadyBound.
	sessB, tokenB, err := svc.BindUser(ctx, tenantID, tokenA, userB, time.Hour)
	require.ErrorIs(t, err, sessions.ErrSessionAlreadyBound,
		"SEC-SES-14 fixed: BindUser must reject rebinding an already-authenticated session")
	assert.Nil(t, sessB)
	assert.Empty(t, tokenB)

	// Token A remains valid and bound to User A (not rotated or reassigned)
	validated, err := svc.ValidateSession(ctx, tenantID, tokenA)
	require.NoError(t, err)
	assert.Equal(t, userA, validated.UserID)
	assert.Equal(t, sessA.ID, validated.ID)
}

// SEC-SES-07 (CVSS 7.5): Paniques silencieusement avalées dans le Janitor.
// janitor.Start with panic handling must report panics instead of swallowing them silently.
func TestSecSes07_JanitorSwallowsPanicsSilently(t *testing.T) {
	var panicked atomic.Bool
	var panicHandled atomic.Bool
	var recoveredValue atomic.Value

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := janitor.Start(ctx, 5*time.Millisecond, func() {
		if !panicked.Swap(true) {
			panic("simulated fatal store connection failure")
		}
	}, janitor.WithPanicHandler(func(recovered any) {
		panicHandled.Store(true)
		recoveredValue.Store(recovered)
	}))

	time.Sleep(30 * time.Millisecond)
	j.Stop()

	assert.True(t, panicked.Load(), "Callback panicked on first run")
	assert.True(t, panicHandled.Load(),
		"SEC-SES-07 fixed: Janitor reports panic via WithPanicHandler instead of silently swallowing it")
	assert.Equal(t, "simulated fatal store connection failure", recoveredValue.Load())
}

// SEC-SES-08 (CVSS 4.3): Non-idempotence de RevokeSession et évasion des logs d'audit sur sessions expirées.
// Calling RevokeSession a second time or on an expired session succeeds (idempotent) and emits event.Logout.
func TestSecSes08_RevokeSessionNonIdempotentAndAuditEvasion(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()

	var logoutEvents atomic.Int64
	sink := event.SinkFunc(func(ctx context.Context, e event.Event) {
		if e.Type == event.Logout {
			logoutEvents.Add(1)
		}
	})

	svc := sessions.NewService(store, sessions.WithEventSink(sink))
	tenantID := "tenant-sec08"
	userID := uuid.Must(uuid.NewV7())

	_, token, err := svc.CreateSession(ctx, tenantID, userID, "UA", "127.0.0.1", time.Hour)
	require.NoError(t, err)

	// First revocation succeeds and emits event.Logout
	err = svc.RevokeSession(ctx, tenantID, token)
	require.NoError(t, err)
	assert.Equal(t, int64(1), logoutEvents.Load())

	// Remediated behavior 1: Second revocation succeeds without error (idempotent)
	err = svc.RevokeSession(ctx, tenantID, token)
	require.NoError(t, err,
		"SEC-SES-08 fixed: RevokeSession is idempotent and returns nil on already-revoked session")

	// Remediated behavior 2: Logout audit event is emitted on subsequent revoke attempt
	assert.Equal(t, int64(2), logoutEvents.Load(),
		"SEC-SES-08 fixed: Logout event emitted on subsequent revoke attempt")
}

// SEC-SES-10: Origin validation in internal/httputil (Cross-Scheme & Permissive Default).
// RequestOriginURL preserves scheme and host, cross-scheme (HTTP origin targeting HTTPS endpoint)
// is rejected, and OriginAllowed does not fail-open when trustedOrigins is empty.
func TestSecSes10_OriginAllowed_CrossSchemeAndPermissiveDefault(t *testing.T) {
	req, err := http.NewRequest("POST", "https://example.com/sensitive-action", nil)
	require.NoError(t, err)

	// Cross-Scheme: unencrypted HTTP origin targeting HTTPS endpoint must be rejected.
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	originURL := httputil.RequestOriginURL(req)
	require.NotNil(t, originURL)
	assert.Equal(t, "http", originURL.Scheme)
	assert.Equal(t, "example.com", originURL.Host)

	// OriginAllowed rejects cross-scheme HTTP origin even if host matches.
	allowed := httputil.OriginAllowed(req, map[string]bool{"example.com": true})
	assert.False(t, allowed, "Cross-scheme HTTP origin targeting HTTPS endpoint must be rejected")

	// Same-scheme HTTPS origin targeting HTTPS endpoint is allowed.
	reqHTTPS, err := http.NewRequest("POST", "https://example.com/sensitive-action", nil)
	require.NoError(t, err)
	reqHTTPS.Header.Set("Origin", "https://example.com")
	reqHTTPS.Host = "example.com"
	allowedHTTPS := httputil.OriginAllowed(reqHTTPS, nil)
	assert.True(t, allowedHTTPS, "Matching HTTPS origin must be allowed with empty trustedOrigins")

	// Secure-by-default: empty trustedOrigins map rejects foreign origins (fail-closed).
	reqForeign, err := http.NewRequest("POST", "https://example.com/api", nil)
	require.NoError(t, err)
	reqForeign.Header.Set("Origin", "https://evil.attacker.com")
	reqForeign.Host = "example.com"

	allowedForeign := httputil.OriginAllowed(reqForeign, map[string]bool{})
	assert.False(t, allowedForeign, "OriginAllowed must not fail-open when trustedOrigins is empty")
}
