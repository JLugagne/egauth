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

// SEC-SES-01 (CVSS 7.5): Éviction de sessions actives légitimes dans sessions/memory.BoundedStore.
// When BoundedStore reaches capacity and no expired sessions exist, it evicts active live sessions
// with the soonest expiry, causing sudden 401 Unauthorized / forced logouts for legitimate users.
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
	require.NoError(t, store.CreateSession(ctx, "tenant-1", sess3))

	// 3. Confirm flawed behavior: Store is still capped at 2, but live Session 1 was prematurely evicted!
	assert.Equal(t, cap, store.Len())

	_, err := store.FindSessionByHash(ctx, "tenant-1", tokenHash1)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"Flaw confirmed: Active, non-expired Session 1 was evicted to make room for Session 3")

	// Session 2 and Session 3 remain
	found2, err := store.FindSessionByHash(ctx, "tenant-1", tokenHash2)
	require.NoError(t, err)
	assert.Equal(t, sess2.ID, found2.ID)

	found3, err := store.FindSessionByHash(ctx, "tenant-1", tokenHash3)
	require.NoError(t, err)
	assert.Equal(t, sess3.ID, found3.ID)
}

// SEC-SES-06 (CVSS 5.4): Contournement du plafond maxLifetime par CreateSession dans le stockage et le Janitor.
// CreateSession sets ExpiresAt = now.Add(duration) without calling clampExpiry, so stored sessions
// have ExpiresAt far in the future exceeding maxLifetime. While ValidateSession rejects the session
// after maxLifetime, the Janitor/DeleteExpired cannot purge the zombie session for the full duration.
func TestSecSes06_CreateSessionBypassesMaxLifetime_ZombieRetention(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()

	// Virtual clock frozen at T0.
	frozen := time.Now()
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

	// Flawed behavior: session.ExpiresAt is NOT clamped to CreatedAt + maxLifetime.
	assert.Equal(t, frozen.Add(longDuration), sess.ExpiresAt,
		"Flaw confirmed: CreateSession did not clamp initial ExpiresAt to maxLifetime")

	// Advance clock past maxLifetime (e.g. 2 hours later, within 10 hours).
	clockNow = frozen.Add(2 * time.Hour)

	// ValidateSession honors maxLifetime and rejects the session.
	_, err = svc.ValidateSession(ctx, tenantID, token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"ValidateSession correctly rejects session past maxLifetime")

	// BUT the store still holds the zombie session because ExpiresAt is still in the future!
	// DeleteExpired checks sess.ExpiresAt.Before(time.Now()), but ExpiresAt is 10 hours from creation.
	deleted, err := store.DeleteExpired(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted,
		"Flaw confirmed: DeleteExpired cannot purge the zombie session because stored ExpiresAt is far in the future")

	// The session record persists in the store despite being rejected by the service!
	hash := hashToken(token)
	storedSess, err := store.FindSessionByHash(ctx, tenantID, hash)
	require.NoError(t, err, "Zombie session remains retained in the store")
	assert.Equal(t, sess.ID, storedSess.ID)
}

// SEC-SES-09 (CVSS 4.0): Boucle CPU intensive (Busy Loop) dans janitor.Start sur intervalle non positif.
// janitor.Start clamps non-positive intervals to time.Nanosecond, starting a 1ns ticker that
// spins a goroutine continuously at 100% CPU.
func TestSecSes09_JanitorBusyLoopOnNonPositiveInterval(t *testing.T) {
	var executions atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Calling Start with interval <= 0 triggers the 1ns fallback.
	j := janitor.Start(ctx, 0, func() {
		executions.Add(1)
	})

	// Wait 25ms — with a 1ns ticker, the callback executes hundreds/thousands of times.
	time.Sleep(25 * time.Millisecond)
	j.Stop()

	count := executions.Load()
	assert.Greater(t, count, int64(50),
		"Flaw confirmed: interval <= 0 resulted in a high-frequency busy loop (>50 executions in 25ms)")
}

// SEC-SES-14 (CVSS 4.2): Réassignation arbitraire d'identité utilisateur dans sessions.Service.BindUser.
// BindUser blindly overwrites session.UserID without checking if session.UserID was already set
// to an authenticated user (i.e. not uuid.Nil), mutating an existing user's session into another user's.
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
	// Expected secure behavior: should reject with an error ("cannot bind already authenticated session").
	// Current flawed behavior: successfully reassigns session to User B while keeping original session ID and CreatedAt.
	sessB, tokenB, err := svc.BindUser(ctx, tenantID, tokenA, userB, time.Hour)
	require.NoError(t, err, "Flaw confirmed: BindUser allows rebinding an already-authenticated session")
	assert.Equal(t, userB, sessB.UserID)
	assert.Equal(t, sessA.ID, sessB.ID, "Session ID was preserved across different user identities")
	assert.Equal(t, sessA.CreatedAt, sessB.CreatedAt, "CreatedAt was preserved")

	// Token A no longer validates (rotated)
	_, err = svc.ValidateSession(ctx, tenantID, tokenA)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound)

	// Token B validates as User B
	validated, err := svc.ValidateSession(ctx, tenantID, tokenB)
	require.NoError(t, err)
	assert.Equal(t, userB, validated.UserID)
}

// SEC-SES-07 (CVSS 7.5): Paniques silencieusement avalées dans le Janitor.
// janitor.Start swallows panics with `_ = recover()` without logging or error notification.
func TestSecSes07_JanitorSwallowsPanicsSilently(t *testing.T) {
	var panicked atomic.Bool
	var ranAfterPanic atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := janitor.Start(ctx, 5*time.Millisecond, func() {
		if !panicked.Swap(true) {
			panic("simulated fatal store connection failure")
		}
		ranAfterPanic.Store(true)
	})

	time.Sleep(30 * time.Millisecond)
	j.Stop()

	assert.True(t, panicked.Load(), "Callback panicked on first run")
	assert.True(t, ranAfterPanic.Load(),
		"Flaw confirmed: Janitor silently swallowed the panic and continued ticking without alerting or stopping")
}

// SEC-SES-08 (CVSS 4.3): Non-idempotence de RevokeSession et évasion des logs d'audit sur sessions expirées.
// Calling RevokeSession a second time or on an expired session returns ErrSessionNotFound and skips event.Logout.
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

	// Flawed behavior 1: Second revocation fails with ErrSessionNotFound (not idempotent)
	err = svc.RevokeSession(ctx, tenantID, token)
	assert.ErrorIs(t, err, sessions.ErrSessionNotFound,
		"Flaw confirmed: RevokeSession is non-idempotent and returns ErrSessionNotFound on second call")

	// Flawed behavior 2: No audit event emitted on duplicate/already-revoked logout
	assert.Equal(t, int64(1), logoutEvents.Load(),
		"Flaw confirmed: No logout event emitted on subsequent revoke attempt")
}

// SEC-SES-10 (CVSS 6.8): Faiblesses de validation d'origine dans internal/httputil (Cross-Scheme & Permissive Default).
// RequestOriginHost strips http vs https scheme allowing cross-scheme matching, and OriginAllowed fails-open when empty.
func TestSecSes10_OriginAllowed_CrossSchemeAndPermissiveDefault(t *testing.T) {
	req, err := http.NewRequest("POST", "https://example.com/sensitive-action", nil)
	require.NoError(t, err)

	// Cross-Scheme: unencrypted HTTP origin targeting HTTPS endpoint.
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	originHost := httputil.RequestOriginHost(req)
	assert.Equal(t, "example.com", originHost, "Flaw confirmed: RequestOriginHost strips scheme (http://)")

	// OriginAllowed matches host == r.Host regardless of scheme!
	allowed := httputil.OriginAllowed(req, map[string]bool{"example.com": true})
	assert.True(t, allowed, "Flaw confirmed: Cross-scheme origin allowed to match HTTPS host")

	// Permissive default: empty trustedOrigins map allows all requests (fail-open)
	reqForeign, err := http.NewRequest("POST", "https://example.com/api", nil)
	require.NoError(t, err)
	reqForeign.Header.Set("Origin", "https://evil.attacker.com")
	reqForeign.Host = "example.com"

	allowedForeign := httputil.OriginAllowed(reqForeign, map[string]bool{})
	assert.True(t, allowedForeign, "Flaw confirmed: OriginAllowed is fail-open when trustedOrigins is empty")
}
