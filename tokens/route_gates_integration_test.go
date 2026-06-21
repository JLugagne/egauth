// Package tokens_test contains the IC-5 integration proof for WithRequiredKind and
// WithRequiredScopes in a realistic multi-route mux scenario.
//
// Unlike the unit tests in middleware_kind_test.go and middleware_scopes_test.go —
// which exercise the gates in isolation with mock verifiers — these tests spin up a
// real httptest.Server backed by a real jwt.Service (no mocks) with three routes:
//
//   - /kind-gated   — wrapped with RequireMachine (only egauth.Service tokens pass)
//   - /scope-gated  — wrapped with WithRequiredScopes("x") (token must carry scope "x")
//   - /open         — no gate at all (any valid credential passes)
//
// Tokens are issued via IssueTokenPair with the appropriate Kind / Scopes fields set
// on the claims, which the JWT round-trip preserves exactly. This lets VerifyAccessTokenForTenant
// return the correct principal kind and scopes to the middleware gate logic.
//
// IC-5: WithRequiredKind(Service) rejects a PAT/user token and admits a Service token;
//
//	WithRequiredScopes("x") rejects a token without "x" and admits one with it;
//	an unguarded route admits any valid credential.
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

// routeGatesService returns a real jwt.Service usable as both issuer and verifier for
// the IC-5 route-gate integration tests.
func routeGatesService(t *testing.T) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "route-gates-secret-aaaaaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-route-gates-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// routeGatesIssue mints an access token with the given principal kind and scopes.
// Passing kind="" produces an interactive (zero-Kind) user token — identical to what
// IssueTokenPair would produce for a plain interactive session.
func routeGatesIssue(t *testing.T, svc *jwt.Service[struct{}], kind egauth.PrincipalKind, scopes ...string) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
		Kind:    kind,
		Scopes:  scopes,
	})
	require.NoError(t, err)
	return pair.AccessToken
}

// routeGatesMux builds a real http.ServeMux with three routes demonstrating IC-5:
//
//   - /kind-gated  — RequireMachine: only Service tokens pass; PAT/User are rejected.
//   - /scope-gated — WithRequiredScopes("x"): token must carry scope "x".
//   - /open        — no gate: any authenticated credential reaches the handler.
//
// Each handler records whether it was reached via the corresponding bool pointer.
func routeGatesMux(
	svc *jwt.Service[struct{}],
	kindReached *bool,
	scopeReached *bool,
	openReached *bool,
) http.Handler {
	mux := http.NewServeMux()

	// /kind-gated: machine-only route — rejects PAT and interactive User tokens.
	mux.Handle("/kind-gated", tokens.RequireAuth[struct{}](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			*kindReached = true
			w.WriteHeader(http.StatusOK)
		},
		tokens.RequireMachine[struct{}](),
	))

	// /scope-gated: requires scope "x" — any token lacking it is rejected.
	mux.Handle("/scope-gated", tokens.RequireAuth[struct{}](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			*scopeReached = true
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithRequiredScopes[struct{}]("x"),
	))

	// /open: no gate — any valid credential passes through.
	mux.Handle("/open", tokens.RequireAuth[struct{}](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			*openReached = true
			w.WriteHeader(http.StatusOK)
		},
		// No gate options — deliberately ungated.
	))

	return mux
}

// TestRouteGates is the IC-5 integration proof: a single httptest.Server with three
// routes, each guarded differently, verifying that the right credential is admitted
// and the wrong one is rejected — end-to-end with no mocks.
func TestRouteGates(t *testing.T) {
	svc := routeGatesService(t)

	// Mint three distinct tokens via IssueTokenPair. Kind is embedded in the JWT and
	// returned verbatim by VerifyAccessTokenForTenant, so the middleware gate receives
	// the correct principal kind without any mocking.
	serviceToken := routeGatesIssue(t, svc, egauth.Service)
	patToken := routeGatesIssue(t, svc, egauth.PAT)
	userToken := routeGatesIssue(t, svc, "") // zero Kind == interactive User session

	scopedToken := routeGatesIssue(t, svc, "", "x", "y") // carries scope "x"
	unscopedToken := routeGatesIssue(t, svc, "")         // no scopes at all

	// bearerReq builds a GET to the server's path with an Authorization: Bearer header.
	bearerReq := func(t *testing.T, srv *httptest.Server, path, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, srv.URL+path, nil,
		)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	// --- IC-5a: WithRequiredKind (RequireMachine) ---

	t.Run("kind-gate: Service token is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/kind-gated", serviceToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, kindReached, "Service token must reach the kind-gated handler")
	})

	t.Run("kind-gate: PAT token is rejected (403 wrong_principal_kind)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/kind-gated", patToken)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, kindReached, "PAT token must not reach the kind-gated handler")
	})

	t.Run("kind-gate: interactive User token is rejected (403 wrong_principal_kind)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/kind-gated", userToken)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, kindReached, "User token must not reach the kind-gated handler")
	})

	// --- IC-5b: WithRequiredScopes ---

	t.Run("scope-gate: token with scope 'x' is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/scope-gated", scopedToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, scopeReached, "token carrying scope 'x' must reach the scope-gated handler")
	})

	t.Run("scope-gate: token without scope 'x' is rejected (403 insufficient_scope)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/scope-gated", unscopedToken)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, scopeReached, "token lacking scope 'x' must not reach the scope-gated handler")
	})

	// --- IC-5c: unguarded route admits any valid credential ---

	t.Run("open route: Service token is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/open", serviceToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, openReached, "Service token must reach the ungated open route")
	})

	t.Run("open route: PAT token is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/open", patToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, openReached, "PAT token must reach the ungated open route")
	})

	t.Run("open route: User token is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/open", userToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, openReached, "User token must reach the ungated open route")
	})

	t.Run("open route: token without scopes is admitted (200)", func(t *testing.T) {
		var kindReached, scopeReached, openReached bool
		srv := httptest.NewServer(routeGatesMux(svc, &kindReached, &scopeReached, &openReached))
		t.Cleanup(srv.Close)

		resp := bearerReq(t, srv, "/open", unscopedToken)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, openReached, "token without scopes must still reach the ungated open route")
	})
}
