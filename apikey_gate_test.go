package egauth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/store/tokens"
)

func apiRoutes(w *gateWorld, s *seen) http.Handler {
	return w.build(w.a.Routes().
		ProtectAPI("GET /api/items", s.handler, egauth.Kinds("service"), egauth.RequireAnyScope("items:read")).
		ProtectAPI("POST /api/items", s.handler, egauth.Kinds("service", "pat"), egauth.RequireAllScopes("items:write")).
		Protect("GET /account", s.handler))
}

func TestProtectAPIServesADeclaredKindWithIntersectedClaims(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("hank@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read", "items:delete"}, Roles: []string{"user", "admin"}})

	rec := w.request(h, http.MethodGet, "/api/items", credentials{bearer: key})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	p := s.last(t)
	require.Equal(t, egauth.APIKey, p.Kind())
	require.Equal(t, sub, p.Subject())
	info, ok := p.APIKey()
	require.True(t, ok)
	require.Equal(t, "service", info.Kind)
	require.Equal(t, sub, info.Owner)
	c := p.Claims()
	require.Equal(t, []string{"items:read"}, c.Scopes, "items:delete is not held by the owner")
	require.Equal(t, []string{"user"}, c.Roles, "admin is not held by the owner")
	require.Equal(t, "pro", c.Custom.Plan, "Custom comes from the owner")
	_, isSession := p.Session()
	require.False(t, isSession)

	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodPost, "/api/items", credentials{bearer: key}).Code,
		"items:write was not granted to the key")
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", credentials{bearer: key}).Code)
}

func TestProtectAPIRefusesAnUndeclaredKindAndSessions(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("ivy@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	pat := w.createAPIKey(sub, "pat", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: pat}).Code)

	c := w.login(h, "ivy@example.com", false)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", c).Code)
	b := w.login(h, "ivy@example.com", true)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", b).Code)

	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	withCookie := credentials{bearer: key, cookies: c.cookies}
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", withCookie).Code)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key + "x"}).Code)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{}).Code)
	require.Equal(t, 0, s.count())
}

func TestProtectAPIOwnerStateMakesTheKeyUnusable(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("jack@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)

	w.disable(sub, true)
	w.clk.Advance(revoke.PollBound)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code,
		"the epoch bump of a disable reaches the cached key within PollBound, before RecheckEvery")
	w.disable(sub, false)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
}

func TestProtectAPIRevokedAndExpiredKeysAreRefused(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("kate@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	keys, err := w.st.Tokens.ListAPIKeys(context.Background(), sub)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.NoError(t, w.st.Tokens.RevokeAPIKey(context.Background(), sub, keys[0].ID))
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)

	short := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}}, func(k *tokens.APIKey) {
		k.ExpiresAt = w.clk.Now().Add(time.Minute)
	})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: short}).Code)
	w.clk.Advance(2 * time.Minute)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: short}).Code)
}

func TestProtectAPIRecomputesClaimsEveryRecheckEvery(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("liam@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	calls := w.claims.count()
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	require.Equal(t, calls, w.claims.count(), "claims are cached within RecheckEvery")

	w.claims.set(sub, egauth.AppClaims[gateClaims]{Roles: []string{"user"}})
	w.clk.Advance(egauth.ConfigOf(w.a).Policy.RecheckEvery - time.Second)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	w.clk.Advance(2 * time.Second)
	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code,
		"the owner lost items:read, so the key lost it within RecheckEvery")
	require.Greater(t, w.claims.count(), calls)
}

func TestProtectAPIKeyOfAnotherTenantIsNotFound(t *testing.T) {
	w := newGateWorld(t, perRequestTenancy)
	w.tenant = "acme"
	sub := w.seedUser("mia@example.com", false)
	s := &seen{}
	h := apiRoutes(w, s)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	other := func(r *http.Request) { r.Header.Set(gateTenantHdr, "globex") }
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}, other).Code)
}
