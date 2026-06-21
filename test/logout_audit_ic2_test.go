// TestLogoutAudited is the IC-2 integration proof for milestone M9-audit-completeness.
//
// IC-2 (logout audited everywhere): every logout path — token/refresh model and session model —
// produces a logout event carrying the client IP and User-Agent, and no captured event ever
// carries a secret (token value or hash).
//
// The test exercises:
//  1. tokens.LogoutHandler configured with tokens.WithEventSink: a successful family revoke emits
//     event.Logout (Reason="token_logout") with the client IP/UA.
//  2. sessions.Service.RevokeSession (single sign-out): emits event.Logout carrying the client
//     IP/UA from the supplied event.RequestContext.
//  3. sessions.Service.RevokeAllForUser ("log out everywhere"): emits event.Logout
//     (Reason="all_sessions") carrying the client IP/UA.
//
// All sub-tests share the auditSink helper already defined in audit_trail_integration_test.go
// (same package).
package internal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/sessions"
	sessionsmemory "github.com/JLugagne/egauth/sessions/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokensmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogoutAudited is the IC-2 integration-verify test: every logout path emits a logout event
// with the client IP, and no captured event carries a secret token or hash.
func TestLogoutAudited(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-ic2"
	const clientIP = "203.0.113.99"
	const userAgent = "egauth-ic2-test/1.0"

	// -------------------------------------------------------------------------
	// Sub-test 1: token/refresh logout via LogoutHandler + WithEventSink
	// -------------------------------------------------------------------------

	t.Run("token-model: LogoutHandler emits logout(token_logout) with IP and UserAgent", func(t *testing.T) {
		// Wire a single in-memory store shared between the jwt.Service (which persists the
		// refresh token on IssueTokenPair) and the LogoutHandler (which looks it up via
		// FindRefreshToken). TenantID is empty: the handler's default tenant resolver returns ""
		// and the store's FindRefreshToken looks up by (tenantID="", hash), which matches.
		store := tokensmemory.NewStore[struct{}]()
		svc := jwt.New[struct{}](jwt.Config[struct{}]{
			Store:      store,
			SecretKey:  "ic2-logout-audit-secret-key-----",
			Issuer:     "egauth-ic2-test",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 24 * time.Hour,
		})

		userID := uuid.Must(uuid.NewV7())
		pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
			Subject: userID,
			// TenantID intentionally empty: single-tenant partition; the handler's default
			// tenant resolver ("") matches the stored record.
		})
		require.NoError(t, err)

		sink := &auditSink{}
		h := tokens.LogoutHandler(
			store,
			tokens.WithEventSink(sink),
			tokens.WithInsecureNoOriginCheck(),
		)

		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.AddCookie(&http.Cookie{
			Name:  tokens.DefaultRefreshCookieName,
			Value: pair.RefreshToken,
		})
		req.RemoteAddr = clientIP + ":55123"
		req.Header.Set("User-Agent", userAgent)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code)

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "LogoutHandler must emit event.Logout after successful family revoke")
		assert.Equal(t, "token_logout", e.Reason, "Reason must be token_logout")
		assert.Equal(t, userID.String(), e.UserID, "UserID must match the token owner")
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP], "client IP must be present in Attrs")
		assert.Equal(t, userAgent, e.Attrs[event.AttrUserAgent], "User-Agent must be present in Attrs")

		// The refresh token and its hash must never appear verbatim in any emitted event.
		assertNoSecrets(t, sink, pair.RefreshToken, pair.RefreshTokenHash)
	})

	// -------------------------------------------------------------------------
	// Sub-test 2: session model sign-out (RevokeSession) carries IP
	// -------------------------------------------------------------------------

	t.Run("session-model: RevokeSession emits logout with IP and UserAgent", func(t *testing.T) {
		sink := &auditSink{}
		store := sessionsmemory.NewStore()
		svc := sessions.NewService(store, sessions.WithEventSink(sink))

		userID := uuid.Must(uuid.NewV7())
		session, token, err := svc.CreateSession(ctx, tenant, userID, userAgent, clientIP, time.Hour)
		require.NoError(t, err)
		require.NotNil(t, session)

		sink.reset()

		rc := event.RequestContext{IP: clientIP, UserAgent: userAgent}
		require.NoError(t, svc.RevokeSession(ctx, tenant, token, rc))

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "RevokeSession must emit event.Logout")
		assert.Equal(t, tenant, e.TenantID)
		assert.Equal(t, userID.String(), e.UserID)
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP], "client IP must be recorded in Attrs")
		assert.Equal(t, userAgent, e.Attrs[event.AttrUserAgent], "User-Agent must be recorded in Attrs")

		// The raw session token must never appear verbatim in any event.
		assertNoSecrets(t, sink, token)
	})

	// -------------------------------------------------------------------------
	// Sub-test 3: session model "log out everywhere" (RevokeAllForUser) carries IP
	// -------------------------------------------------------------------------

	t.Run("session-model: RevokeAllForUser emits logout(all_sessions) with IP and UserAgent", func(t *testing.T) {
		sink := &auditSink{}
		store := sessionsmemory.NewStore()
		svc := sessions.NewService(store, sessions.WithEventSink(sink))

		userID := uuid.Must(uuid.NewV7())
		_, token1, err := svc.CreateSession(ctx, tenant, userID, userAgent, clientIP, time.Hour)
		require.NoError(t, err)
		_, token2, err := svc.CreateSession(ctx, tenant, userID, userAgent, clientIP, time.Hour)
		require.NoError(t, err)

		sink.reset()

		rc := event.RequestContext{IP: clientIP, UserAgent: userAgent}
		require.NoError(t, svc.RevokeAllForUser(ctx, tenant, userID, rc))

		e, ok := sink.find(event.Logout)
		require.True(t, ok, "RevokeAllForUser must emit event.Logout")
		assert.Equal(t, "all_sessions", e.Reason, "Reason must be all_sessions for log-out-everywhere")
		assert.Equal(t, tenant, e.TenantID)
		assert.Equal(t, userID.String(), e.UserID)
		assert.Equal(t, clientIP, e.Attrs[event.AttrIP], "client IP must be recorded in Attrs")
		assert.Equal(t, userAgent, e.Attrs[event.AttrUserAgent], "User-Agent must be recorded in Attrs")

		// The raw session tokens must never appear verbatim in any event.
		assertNoSecrets(t, sink, token1, token2)
	})
}
