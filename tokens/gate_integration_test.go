// Package tokens_test contains integration tests that prove SC-4 (password-change gate)
// in a realistic multi-route mux scenario. Unlike the unit tests in
// middleware_gate_test.go — which exercise individual handlers in isolation — these
// tests spin up a real httptest.Server with two routes:
//
//   - /protected  — wrapped with WithPasswordChangeGate (the "must change password" gate)
//   - /change     — NOT wrapped with the gate (the escape-hatch / change-password route)
//
// Both routes use the same jwt.Service as both issuer and verifier (no mocks), making
// this a genuine end-to-end integration proof.
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

// integrationService returns a real jwt.Service usable as both issuer and verifier.
func integrationService(t *testing.T) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "integ-secret-aaaaaaaaaaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-integ-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// integrationIssue mints an access token flagged or not with MustChangePassword.
func integrationIssue(t *testing.T, svc *jwt.Service[struct{}], mustChange bool) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:            uuid.Must(uuid.NewV7()),
		MustChangePassword: mustChange,
	})
	require.NoError(t, err)
	return pair.AccessToken
}

// integrationMux builds a real http.ServeMux with two routes:
//   - /protected is wrapped with WithPasswordChangeGate using the provided resetURL.
//   - /change    is NOT wrapped with the gate (the escape hatch).
//
// Each handler records whether it was reached via the corresponding bool pointer.
func integrationMux(
	svc *jwt.Service[struct{}],
	resetURL string,
	protectedReached *bool,
	changeReached *bool,
) http.Handler {
	mux := http.NewServeMux()

	// Gated route — the gate fires on flagged tokens.
	mux.Handle("/protected", tokens.RequireAuth[struct{}](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			*protectedReached = true
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithPasswordChangeGate[struct{}](resetURL),
	))

	// Ungated route — the change-password / logout escape hatch.
	mux.Handle("/change", tokens.RequireAuth[struct{}](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			*changeReached = true
			w.WriteHeader(http.StatusOK)
		},
		// No WithPasswordChangeGate — deliberately ungated.
	))

	return mux
}

// bearerRequest builds a GET request to path with an Authorization: Bearer header.
func bearerRequest(t *testing.T, srv *httptest.Server, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestPasswordGate_Integration proves SC-4 in a multi-route mux context:
// a single httptest.Server with one gated route and one ungated escape-hatch route.
func TestPasswordGate_Integration(t *testing.T) {
	svc := integrationService(t)

	flaggedToken := integrationIssue(t, svc, true)
	cleanToken := integrationIssue(t, svc, false)

	t.Run("flagged token on gated route with reset URL redirects 303", func(t *testing.T) {
		var protectedReached, changeReached bool
		srv := httptest.NewServer(integrationMux(svc, "/account/reset-password", &protectedReached, &changeReached))
		t.Cleanup(srv.Close)

		// Disable redirect following so we can inspect the 303.
		srv.Client().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp := bearerRequest(t, srv, "/protected", flaggedToken)

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Location"), "/account/reset-password")
		assert.False(t, protectedReached, "gated handler must not be reached when gate fires")
	})

	t.Run("flagged token on gated route without reset URL returns 403", func(t *testing.T) {
		var protectedReached, changeReached bool
		srv := httptest.NewServer(integrationMux(svc, "", &protectedReached, &changeReached))
		t.Cleanup(srv.Close)

		resp := bearerRequest(t, srv, "/protected", flaggedToken)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, protectedReached, "gated handler must not be reached when gate fires")
	})

	t.Run("clean token on gated route passes through", func(t *testing.T) {
		var protectedReached, changeReached bool
		srv := httptest.NewServer(integrationMux(svc, "/account/reset-password", &protectedReached, &changeReached))
		t.Cleanup(srv.Close)

		resp := bearerRequest(t, srv, "/protected", cleanToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, protectedReached, "clean token must reach the gated handler")
	})

	t.Run("flagged token on ungated route reaches handler", func(t *testing.T) {
		// This is the key escape-hatch scenario: the same flagged token that is
		// rejected on /protected must still reach /change (no gate configured).
		var protectedReached, changeReached bool
		srv := httptest.NewServer(integrationMux(svc, "/account/reset-password", &protectedReached, &changeReached))
		t.Cleanup(srv.Close)

		resp := bearerRequest(t, srv, "/change", flaggedToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, changeReached, "flagged token must still reach the ungated change-password route")
		assert.False(t, protectedReached, "the gated handler was not invoked")
	})
}
