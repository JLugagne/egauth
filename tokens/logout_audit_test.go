package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogoutHandlerAudit covers the WithEventSink audit emission on the token/refresh
// LogoutHandler: a successful family revoke emits event.Logout (Reason="token_logout") carrying
// the user, the client IP/User-Agent; a nil sink is a no-op; and the idempotent paths (no cookie,
// already-gone token) emit nothing.
func TestLogoutHandlerAudit(t *testing.T) {
	t.Run("successful logout emits token_logout with IP and UserAgent", func(t *testing.T) {
		ctx := context.Background()
		svc, store := newRotator(t)
		userID := uuid.Must(uuid.NewV7())
		pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
		require.NoError(t, err)

		sink := &captureSink{}
		h := tokens.LogoutHandler(store, tokens.WithEventSink(sink))

		req := postWithRefresh(pair.RefreshToken)
		req.RemoteAddr = "203.0.113.7:54321"
		req.Header.Set("User-Agent", "egauth-test-agent/1.0")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)

		logouts := sink.ofType(event.Logout)
		require.Len(t, logouts, 1, "expected exactly one logout event")
		e := logouts[0]
		assert.Equal(t, "token_logout", e.Reason)
		assert.Equal(t, userID.String(), e.UserID)
		assert.Equal(t, "203.0.113.7", e.Attrs[event.AttrIP], "client IP host (no port) must be recorded")
		assert.Equal(t, "egauth-test-agent/1.0", e.Attrs[event.AttrUserAgent])

		// The event must never carry the token or its hash.
		for k, v := range e.Attrs {
			assert.NotEqual(t, pair.RefreshToken, v, "refresh token leaked into Attrs[%q]", k)
			assert.NotEqual(t, tokens.HashToken(pair.RefreshToken), v, "token hash leaked into Attrs[%q]", k)
		}
	})

	t.Run("nil sink is a no-op", func(t *testing.T) {
		ctx := context.Background()
		svc, store := newRotator(t)
		pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
		require.NoError(t, err)

		// No WithEventSink: a nil sink must not panic and must not change the response.
		h := tokens.LogoutHandler(store)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postWithRefresh(pair.RefreshToken))

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("logout without a cookie emits nothing", func(t *testing.T) {
		_, store := newRotator(t)
		sink := &captureSink{}
		h := tokens.LogoutHandler(store, tokens.WithEventSink(sink))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postWithRefresh(""))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, sink.ofType(event.Logout), "no token, no sign-out to audit")
	})

	t.Run("already-gone token emits nothing", func(t *testing.T) {
		_, store := newRotator(t)
		sink := &captureSink{}
		h := tokens.LogoutHandler(store, tokens.WithEventSink(sink))

		// A token that was never stored resolves to ErrRefreshTokenNotFound: idempotent success,
		// but no fresh logout to record.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postWithRefresh("never-issued-token"))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, sink.ofType(event.Logout), "double-logout must not manufacture a logout event")
	})
}
