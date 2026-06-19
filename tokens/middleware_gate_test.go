package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gateService() *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "gate-secret-aaaaaaaaaaaaaaaaaaaa", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// gateIssue mints an access token, optionally flagged with MustChangePassword.
func gateIssue(t *testing.T, svc *jwt.Service[struct{}], mustChange bool) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:            uuid.Must(uuid.NewV7()),
		MustChangePassword: mustChange,
	})
	require.NoError(t, err)
	return pair.AccessToken
}

// gateCall runs the bearer token through the handler and returns the recorder.
func gateCall(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequireAuth_PasswordChangeGate(t *testing.T) {
	svc := gateService()

	// next records whether the protected handler was reached.
	var reached bool
	protected := func(opts ...tokens.AuthOption[struct{}]) http.Handler {
		reached = false
		return tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}, opts...)
	}

	t.Run("flagged token with reset URL redirects 303 to the reset URL", func(t *testing.T) {
		h := protected(tokens.WithPasswordChangeGate[struct{}]("/account/reset"))
		rec := gateCall(h, gateIssue(t, svc, true))

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/account/reset")
		assert.False(t, reached, "next must not be called when the gate fires")
	})

	t.Run("flagged token without reset URL returns 403 password_change_required", func(t *testing.T) {
		h := protected(tokens.WithPasswordChangeGate[struct{}](""))
		rec := gateCall(h, gateIssue(t, svc, true))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "password_change_required")
		assert.False(t, reached, "next must not be called when the gate fires")
	})

	t.Run("flagged token without the gate configured reaches next", func(t *testing.T) {
		h := protected()
		rec := gateCall(h, gateIssue(t, svc, true))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached, "without the gate a flagged token must still authenticate")
	})

	t.Run("clean token with the gate configured reaches next", func(t *testing.T) {
		h := protected(tokens.WithPasswordChangeGate[struct{}]("/account/reset"))
		rec := gateCall(h, gateIssue(t, svc, false))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached, "an unflagged token must pass the gate")
	})
}

func TestContextMiddleware_PasswordChangeGate(t *testing.T) {
	svc := gateService()

	var reached bool
	wrapped := func(opts ...tokens.AuthOption[struct{}]) http.Handler {
		reached = false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
		return tokens.ContextMiddleware[struct{}](svc, next, opts...)
	}

	t.Run("flagged token with reset URL redirects 303", func(t *testing.T) {
		h := wrapped(tokens.WithPasswordChangeGate[struct{}]("/account/reset"))
		rec := gateCall(h, gateIssue(t, svc, true))

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/account/reset")
		assert.False(t, reached)
	})

	t.Run("flagged token without reset URL returns 403", func(t *testing.T) {
		h := wrapped(tokens.WithPasswordChangeGate[struct{}](""))
		rec := gateCall(h, gateIssue(t, svc, true))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "password_change_required")
		assert.False(t, reached)
	})

	t.Run("clean token passes the gate", func(t *testing.T) {
		h := wrapped(tokens.WithPasswordChangeGate[struct{}]("/account/reset"))
		rec := gateCall(h, gateIssue(t, svc, false))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})
}
