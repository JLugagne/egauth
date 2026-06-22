package tokens_test

import (
	"context"
	"errors"
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

// withGateService builds a jwt.Service used by all WithGate subtests.
func withGateService() *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "withgate-secret-aaaaaaaaaaaaaaaaaaa", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// withGateIssue mints a plain access token (no special flags).
func withGateIssue(t *testing.T, svc *jwt.Service[struct{}]) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
	})
	require.NoError(t, err)
	return pair.AccessToken
}

// withGateCall sends the bearer token to the handler and returns the recorder.
func withGateCall(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestWithGate covers the four documented scenarios for RequireAuth (direct-token path)
// and also exercises the auto-refresh path so gate coverage in both branches is verified.
func TestWithGate(t *testing.T) {
	svc := withGateService()
	errDeny := errors.New("policy: resource not allowed")

	// reached tracks whether the protected handler was called.
	var reached bool
	// capturedActor and capturedClaims record what the gate received.
	var capturedActor egauth.Actor
	var capturedClaims struct{}

	// makeHandler builds a RequireAuth handler with the given options; it resets reached
	// before each call so subtests can share the variable safely.
	makeHandler := func(opts ...tokens.AuthOption[struct{}]) http.Handler {
		reached = false
		return tokens.RequireAuth[struct{}](svc,
			func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}, opts...)
	}

	t.Run("allow: nil-returning gate → handler reached, 200", func(t *testing.T) {
		gate := func(_ egauth.Actor, _ struct{}) error { return nil }
		h := makeHandler(tokens.WithGate[struct{}](gate))

		rec := withGateCall(h, withGateIssue(t, svc))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached, "handler must be called when gate returns nil")
	})

	t.Run("deny: error-returning gate → 403, handler NOT reached", func(t *testing.T) {
		gate := func(_ egauth.Actor, _ struct{}) error { return errDeny }
		h := makeHandler(tokens.WithGate[struct{}](gate))

		rec := withGateCall(h, withGateIssue(t, svc))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached, "handler must NOT be called when gate returns error")
		// Error text must NOT be echoed.
		assert.NotContains(t, rec.Body.String(), errDeny.Error())
	})

	t.Run("unset: no gate configured → handler reached, 200", func(t *testing.T) {
		h := makeHandler() // no WithGate

		rec := withGateCall(h, withGateIssue(t, svc))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached, "without a gate the handler must always be called")
	})

	t.Run("sees-claims: gate receives the verified Actor and custom claims", func(t *testing.T) {
		uid := uuid.Must(uuid.NewV7())
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
		require.NoError(t, err)

		gate := func(actor egauth.Actor, custom struct{}) error {
			capturedActor = actor
			capturedClaims = custom
			return nil
		}
		h := makeHandler(tokens.WithGate[struct{}](gate))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, uid, capturedActor.UserID, "gate must see the Subject from the token")
		_ = capturedClaims // struct{} carries no fields; presence of the call is the assertion
	})
}

// TestWithGate_AutoRefreshPath verifies that the gate is also applied on the transparent
// auto-refresh path (expired access token + valid refresh cookie).
func TestWithGate_AutoRefreshPath(t *testing.T) {
	errDeny := errors.New("gate: denied on refresh path")

	// Build the shared store and two services: one for normal tokens and one that
	// mints already-expired access tokens (same store, so refresh tokens are valid).
	store := memory.NewStore[struct{}]()
	commonCfg := jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "withgate-refresh-aaaaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, uid uuid.UUID, tid string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: uid, TenantID: tid}, nil
		}),
	}
	svc := jwt.New[struct{}](commonCfg)

	expiredCfg := commonCfg
	expiredCfg.AccessTTL = -time.Minute
	expiredMinter := jwt.New[struct{}](expiredCfg)

	cookies := tokens.DefaultCookies()

	// Issue an expired access token + valid refresh token via the expiredMinter.
	uid := uuid.Must(uuid.NewV7())
	pair, err := expiredMinter.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
	require.NoError(t, err)

	makeRequest := func(accessVal, refreshVal string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		if accessVal != "" {
			req.AddCookie(&http.Cookie{Name: cookies.AccessName, Value: accessVal})
		}
		if refreshVal != "" {
			req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: refreshVal})
		}
		return req
	}

	t.Run("deny on auto-refresh path: gate returns error → 403, handler NOT reached", func(t *testing.T) {
		reached := false
		gate := func(_ egauth.Actor, _ struct{}) error { return errDeny }

		h := tokens.RequireAuth[struct{}](svc,
			func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
				reached = true
				w.WriteHeader(http.StatusOK)
			},
			tokens.WithAutoRefresh[struct{}](svc, cookies),
			tokens.WithGate[struct{}](gate),
		)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, makeRequest(pair.AccessToken, pair.RefreshToken))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached, "handler must NOT be called when gate denies on the refresh path")
		assert.NotContains(t, rec.Body.String(), errDeny.Error())
	})

	t.Run("allow on auto-refresh path: gate returns nil → handler reached, 200", func(t *testing.T) {
		// Re-issue because the previous subtest may have consumed the refresh token.
		pair2, err := expiredMinter.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid})
		require.NoError(t, err)

		reached := false
		gate := func(_ egauth.Actor, _ struct{}) error { return nil }

		h := tokens.RequireAuth[struct{}](svc,
			func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
				reached = true
				w.WriteHeader(http.StatusOK)
			},
			tokens.WithAutoRefresh[struct{}](svc, cookies),
			tokens.WithGate[struct{}](gate),
		)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, makeRequest(pair2.AccessToken, pair2.RefreshToken))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached, "handler must be called when gate allows on the refresh path")
	})
}
