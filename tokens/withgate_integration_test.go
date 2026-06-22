package tokens_test

// WithGate evaluator end-to-end integration tests.
// Proves IC-3 (custom claims C predicate) and IC-4 (HasAllScopes inside the predicate)
// through a real httptest.Server using a real jwt.Service as both issuer and verifier.
// This file is DISTINCT from gate_integration_test.go (which covers WithPasswordChangeGate).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	egauth "github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withGateClaims is the custom claims type used throughout this file.
// The Role field lets us exercise a predicate that inspects C directly (IC-3).
type withGateClaims struct {
	Role string
}

// withGateIntegrationService returns a real jwt.Service[withGateClaims] usable as
// both issuer and verifier. Mirrors integrationService from gate_integration_test.go
// but parameterised over withGateClaims.
func withGateIntegrationService(t *testing.T) *jwt.Service[withGateClaims] {
	t.Helper()
	return jwt.New[withGateClaims](jwt.Config[withGateClaims]{
		Store:      memory.NewStore[withGateClaims](),
		SecretKey:  "withgate-integ-secret-aaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-withgate-integ-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// withGateIntegrationIssue mints an access token carrying the provided role and scopes.
func withGateIntegrationIssue(t *testing.T, svc *jwt.Service[withGateClaims], role string, scopes ...string) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[withGateClaims]{
		Subject: uuid.Must(uuid.NewV7()),
		Scopes:  scopes,
		Custom:  withGateClaims{Role: role},
	})
	require.NoError(t, err)
	return pair.AccessToken
}

// withGateIntegrationBearerRequest makes a real HTTP GET to srv at path with an
// Authorization: Bearer header. Mirrors bearerRequest from gate_integration_test.go.
func withGateIntegrationBearerRequest(t *testing.T, srv *httptest.Server, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// withGateIntegrationMux builds a real http.ServeMux with three routes:
//
//   - /claims  is gated by a predicate that inspects custom claims C (role == "admin").
//   - /scopes  is gated by a predicate that calls actor.HasAllScopes("write").
//   - /open    has no WithGate — every valid token passes through.
//
// Each handler records whether it was reached via the corresponding bool pointer.
func withGateIntegrationMux(
	svc *jwt.Service[withGateClaims],
	claimsReached *bool,
	scopesReached *bool,
	openReached *bool,
) http.Handler {
	mux := http.NewServeMux()

	// /claims — gate fires unless the token carries Role == "admin" (IC-3).
	mux.Handle("/claims", tokens.RequireAuth[withGateClaims](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ withGateClaims) {
			*claimsReached = true
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithGate[withGateClaims](func(_ egauth.Actor, c withGateClaims) error {
			if c.Role != "admin" {
				return errors.New("gate: role admin required")
			}
			return nil
		}),
	))

	// /scopes — gate fires unless the actor carries the "write" scope (IC-4).
	mux.Handle("/scopes", tokens.RequireAuth[withGateClaims](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ withGateClaims) {
			*scopesReached = true
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithGate[withGateClaims](func(actor egauth.Actor, _ withGateClaims) error {
			if !actor.HasAllScopes("write") {
				return errors.New("gate: write scope required")
			}
			return nil
		}),
	))

	// /open — no gate; every valid token reaches the handler.
	mux.Handle("/open", tokens.RequireAuth[withGateClaims](
		svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ withGateClaims) {
			*openReached = true
			w.WriteHeader(http.StatusOK)
		},
		// No WithGate — deliberately ungated.
	))

	return mux
}

// TestWithGate_Integration proves IC-3 and IC-4 end-to-end through a real
// httptest.Server using a real jwt.Service as issuer and verifier.
func TestWithGate_Integration(t *testing.T) {
	svc := withGateIntegrationService(t)

	// IC-3 — predicate inspects custom claims C (Role field).

	t.Run("IC-3: claims gate denies non-admin role → 403, handler not reached", func(t *testing.T) {
		var claimsReached, scopesReached, openReached bool
		srv := httptest.NewServer(withGateIntegrationMux(svc, &claimsReached, &scopesReached, &openReached))
		t.Cleanup(srv.Close)

		token := withGateIntegrationIssue(t, svc, "user") // role != "admin"
		resp := withGateIntegrationBearerRequest(t, srv, "/claims", token)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, claimsReached, "handler must NOT be reached when claims gate denies")
	})

	t.Run("IC-3: claims gate allows admin role → 200, handler reached", func(t *testing.T) {
		var claimsReached, scopesReached, openReached bool
		srv := httptest.NewServer(withGateIntegrationMux(svc, &claimsReached, &scopesReached, &openReached))
		t.Cleanup(srv.Close)

		token := withGateIntegrationIssue(t, svc, "admin") // role == "admin"
		resp := withGateIntegrationBearerRequest(t, srv, "/claims", token)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, claimsReached, "handler must be reached when claims gate allows")
	})

	// IC-4 — HasAllScopes used inside the predicate.

	t.Run("IC-4: scope gate denies token missing write scope → 403, handler not reached", func(t *testing.T) {
		var claimsReached, scopesReached, openReached bool
		srv := httptest.NewServer(withGateIntegrationMux(svc, &claimsReached, &scopesReached, &openReached))
		t.Cleanup(srv.Close)

		token := withGateIntegrationIssue(t, svc, "", "read") // has "read", not "write"
		resp := withGateIntegrationBearerRequest(t, srv, "/scopes", token)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, scopesReached, "handler must NOT be reached when scope gate denies")
	})

	t.Run("IC-4: scope gate allows token carrying write scope → 200, handler reached", func(t *testing.T) {
		var claimsReached, scopesReached, openReached bool
		srv := httptest.NewServer(withGateIntegrationMux(svc, &claimsReached, &scopesReached, &openReached))
		t.Cleanup(srv.Close)

		token := withGateIntegrationIssue(t, svc, "", "read", "write") // has both scopes
		resp := withGateIntegrationBearerRequest(t, srv, "/scopes", token)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, scopesReached, "handler must be reached when scope gate allows")
	})

	// Unset gate — no WithGate configured on the route.

	t.Run("unset gate: any valid token passes through → 200, handler reached", func(t *testing.T) {
		var claimsReached, scopesReached, openReached bool
		srv := httptest.NewServer(withGateIntegrationMux(svc, &claimsReached, &scopesReached, &openReached))
		t.Cleanup(srv.Close)

		token := withGateIntegrationIssue(t, svc, "") // no role, no scopes — /open has no gate
		resp := withGateIntegrationBearerRequest(t, srv, "/open", token)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, openReached, "handler must be reached when no gate is configured")
	})
}
