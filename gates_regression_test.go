package egauth_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/principal"
)

type slotProbe struct {
	mu    sync.Mutex
	seen  []bool
	inner *ownerClaims
}

func (s *slotProbe) record(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, principalctx.InRequest(ctx))
}

func (s *slotProbe) ClaimsFor(ctx context.Context, sub principal.Subject) (egauth.AppClaims[gateClaims], error) {
	s.record(ctx)
	return s.inner.ClaimsFor(ctx, sub)
}

func (s *slotProbe) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = nil
}

func (s *slotProbe) observed(t *testing.T, what string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.seen, what+" was never reached")
	for i, in := range s.seen {
		require.True(t, in, "%s call %d ran without the principal slot", what, i)
	}
}

func TestGatesEveryServedRequestCarriesThePrincipalSlot(t *testing.T) {
	claims, hook := &slotProbe{}, &slotProbe{}
	w := newGateWorld(t, func(c *egauth.Config[gateClaims]) {
		claims.inner = c.Claims.(*ownerClaims)
		c.Claims = claims
		c.Hooks.BeforeEndpoint = func(ctx context.Context, _ egauth.EndpointRequest) error {
			hook.record(ctx)
			return nil
		}
	})
	sub := w.seedUser("slot@example.com", false)
	s := &seen{}
	h := w.build(w.a.Routes().
		Protect("GET /account", s.handler).
		ProtectAPI("GET /api/items", s.handler, egauth.Kinds("service"), egauth.RequireAnyScope("items:read")))

	c := w.login(h, "slot@example.com", false)
	require.Equal(t, http.StatusOK, c.code, c.body)
	hook.observed(t, "BeforeEndpoint during /auth/login")
	claims.observed(t, "ClaimsFor during /auth/login")

	claims.reset()
	w.clk.Advance(egauth.ConfigOf(w.a).Policy.RecheckEvery + time.Minute)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)
	claims.observed(t, "ClaimsFor during Protect renewal")

	claims.reset()
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/api/items", credentials{bearer: key}).Code)
	claims.observed(t, "ClaimsFor during the ProtectAPI recompute")
}

func TestGatesTenantMismatchDoesNotConsumeTheRefreshToken(t *testing.T) {
	for _, path := range []string{"/account", "/home", "/auth/session"} {
		t.Run(path, func(t *testing.T) {
			w := newGateWorld(t, perRequestTenancy)
			w.tenant = "acme"
			w.seedUser("victim@example.com", false)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)
			c := w.login(h, "victim@example.com", false)
			require.Equal(t, http.StatusOK, c.code, c.body)

			w.clk.Advance(egauth.ConfigOf(w.a).Policy.RecheckEvery + time.Minute)
			other := func(r *http.Request) { r.Header.Set(gateTenantHdr, "globex") }
			rec := w.request(h, http.MethodGet, path, c, other)
			require.Empty(t, rec.Header().Values("Set-Cookie"), "a cross-tenant request writes no cookie")

			w.clk.Advance(30 * time.Second)
			rec = w.request(h, http.MethodGet, "/account", c)
			require.Equal(t, http.StatusOK, rec.Code, "the victim's own session survives a cross-tenant request: %s", rec.Body.String())
			require.Equal(t, egauth.Session, s.last(t).Kind())
		})
	}
}

func TestGatesCookiePlusAuthorizationNeverClearsTheSession(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newGateWorld(t, opt)
			sub := w.seedUser("both@example.com", false)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)
			c := w.login(h, "both@example.com", false)
			require.Equal(t, http.StatusOK, c.code, c.body)
			key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
			both := c
			both.bearer = key

			rec := w.request(h, http.MethodGet, "/home", both)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, egauth.Anonymous, s.last(t).Kind())
			require.False(t, clearsSessionCookies(rec), "an ambiguous request on Optional keeps the session cookies")

			rec = w.request(h, http.MethodGet, "/account", both)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.False(t, clearsSessionCookies(rec), "an ambiguous request on Protect keeps the session cookies")

			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)
			require.Equal(t, egauth.Session, s.last(t).Kind())
		})
	}
}
