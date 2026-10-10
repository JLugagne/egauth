package egauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
)

func protectedItems(rs *egauth.ResourceServer[gateClaims], s *seen) http.Handler {
	h, err := rs.Routes().
		Protect("GET /items", s.handler).
		Protect("GET /admin", s.handler, egauth.RequireAnyRole("admin")).
		Protect("GET /change", s.handler, egauth.AcceptMustChange()).
		Build()
	if err != nil {
		panic(err)
	}
	return h
}

func TestResourceServerAcceptsAResourceTokenForItsAudience(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	s := &seen{}
	h := protectedItems(w.server(), s)

	tok := w.mint("nina@example.com", rsAudience)
	rec := w.call(h, http.MethodGet, "/items", tok)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	p := s.last(t)
	require.Equal(t, egauth.Session, p.Kind())
	claims := p.Claims()
	require.Equal(t, []string{"user"}, claims.Roles)
	require.Equal(t, gateClaims{Plan: "pro"}, claims.Custom)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestResourceServerPrincipalMatchesTheSessionGateOfTheAuth(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	authSeen, rsSeen := &seen{}, &seen{}
	authH, err := w.a.Routes().Protect("GET /whoami", authSeen.handler).Build()
	require.NoError(t, err)
	c := w.login("nina@example.com", false)
	req := httptest.NewRequest(http.MethodGet, w.origin+"/whoami", nil)
	req.Header.Set("Cookie", c.cookieHeader())
	require.Equal(t, http.StatusOK, w.serve(authH, req).Code)
	code, tok := w.resourceToken(c, rsAudience)
	require.Equal(t, http.StatusOK, code)

	require.Equal(t, http.StatusOK, w.call(protectedItems(w.server(), rsSeen), http.MethodGet, "/items", tok).Code)
	want, ok := authSeen.last(t).Session()
	require.True(t, ok)
	got, ok := rsSeen.last(t).Session()
	require.True(t, ok)
	require.True(t, reflect.DeepEqual(want, got), "the resource server decodes the same sealed attributes as Protect")
	require.Equal(t, authSeen.last(t).Claims(), rsSeen.last(t).Claims())
}

func TestResourceServerRefusesTokensThatAreNotForItsAudience(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	s := &seen{}
	h := protectedItems(w.server(), s)

	other := w.mint("nina@example.com", rsOtherAudience)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", other).Code, "another resource's token")

	session := w.login("nina@example.com", true)
	require.NotEmpty(t, session.bearer)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", session.bearer).Code,
		"a session access token (aud = PublicOrigin) is refused: no confused deputy")
	require.Zero(t, s.count())
}

func TestResourceServerCredentialShapes(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	h := protectedItems(w.server(), &seen{})
	tok := w.mint("nina@example.com", rsAudience)
	c := w.login("nina@example.com", false)

	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", "").Code, "no credential")
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", "", func(r *http.Request) {
		r.Header.Set("Cookie", c.cookieHeader())
	}).Code, "a session cookie is no credential for a resource server")
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", tok, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+tok)
	}).Code, "two Authorization headers")
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", "not-a-jwt").Code)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", tok[:len(tok)-4]+"AAAA").Code, "a forged signature")
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", parts[0]+"."+parts[1]+".").Code, "an empty signature")
	require.Equal(t, http.StatusNotFound, w.call(h, http.MethodGet, "/undeclared", tok).Code, "deny by default")
	require.Equal(t, http.StatusOK, w.call(h, http.MethodGet, "/items", tok).Code)
}

func TestResourceServerRefusesAnExpiredToken(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	h := protectedItems(w.server(), &seen{})
	tok := w.mint("nina@example.com", rsAudience)
	require.Equal(t, http.StatusOK, w.call(h, http.MethodGet, "/items", tok).Code)
	w.clk.Advance(egauth.ConfigOf(w.a).Policy.RecheckEvery + time.Minute)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", tok).Code)
}

func TestResourceServerAppliesTheSessionGates(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	w.seedUser("carol@example.com", true)
	h := protectedItems(w.server(), &seen{})

	tok := w.mint("nina@example.com", rsAudience)
	require.Equal(t, http.StatusForbidden, w.call(h, http.MethodGet, "/admin", tok).Code, "a role requirement")

	cc := w.login("carol@example.com", false)
	require.Equal(t, http.StatusOK, cc.code, cc.body)
	code, must := w.resourceToken(cc, rsAudience)
	require.Equal(t, http.StatusForbidden, code, "no resource token is minted for a must-change session")
	require.Empty(t, must)
}

func TestResourceServerRefusesARevokedSessionBeforeItsFirstUse(t *testing.T) {
	w := newRSWorld(t)
	sub := w.seedUser("nina@example.com", false)
	h := protectedItems(w.server(), &seen{})
	tok := w.mint("nina@example.com", rsAudience)
	w.disable(sub)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", tok).Code)
}

func TestResourceServerFollowsRevocationOfACachedSession(t *testing.T) {
	w := newRSWorld(t)
	sub := w.seedUser("nina@example.com", false)
	h := protectedItems(w.server(), &seen{})
	tok := w.mint("nina@example.com", rsAudience)
	require.Equal(t, http.StatusOK, w.call(h, http.MethodGet, "/items", tok).Code)
	w.disable(sub)
	require.Eventually(t, func() bool {
		return w.call(h, http.MethodGet, "/items", tok).Code == http.StatusUnauthorized
	}, 15*time.Second, 50*time.Millisecond)
}

func TestResourceServerRefusesALoggedOutFamily(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	h := protectedItems(w.server(), &seen{})
	c := w.login("nina@example.com", false)
	code, tok := w.resourceToken(c, rsAudience)
	require.Equal(t, http.StatusOK, code)
	req := httptest.NewRequest(http.MethodPost, w.origin+"/auth/logout", nil)
	req.Header.Set("Origin", w.origin)
	req.Header.Set("Cookie", c.cookieHeader())
	require.Less(t, w.serve(w.h, req).Code, 400)
	require.Eventually(t, func() bool {
		return w.call(h, http.MethodGet, "/items", tok).Code == http.StatusUnauthorized
	}, 15*time.Second, 50*time.Millisecond)
}

func TestResourceServerRevocationLagOptOut(t *testing.T) {
	w := newRSWorld(t)
	sub := w.seedUser("nina@example.com", false)
	rs := w.server(func(c *egauth.ResourceConfig) {
		c.Revocation = nil
		c.Insecure.RevocationLagUpToTTL = egauth.Acknowledge("short-lived demo tokens")
	})
	h := protectedItems(rs, &seen{})
	tok := w.mint("nina@example.com", rsAudience)
	w.disable(sub)
	require.Equal(t, http.StatusOK, w.call(h, http.MethodGet, "/items", tok).Code, "the lag is accepted until the token expires")
	w.clk.Advance(egauth.ConfigOf(w.a).Policy.RecheckEvery + time.Minute)
	require.Equal(t, http.StatusUnauthorized, w.call(h, http.MethodGet, "/items", tok).Code)
	evs := w.sink.of(event.InsecureConfiguration)
	require.Len(t, evs, 1)
	require.Equal(t, "revocation_lag_up_to_ttl", evs[0].Reason)
}

func TestResourceServerWithoutOptOutEmitsNoInsecureEvent(t *testing.T) {
	w := newRSWorld(t)
	w.server()
	require.Empty(t, w.sink.of(event.InsecureConfiguration))
}

func TestResourceServerBuildRejectsBadDeclarations(t *testing.T) {
	w := newRSWorld(t)
	rs := w.server()
	h := (&seen{}).handler
	for name, rt := range map[string]*egauth.APIRoutes[gateClaims]{
		"no method":   rs.Routes().Protect("/items", h),
		"host":        rs.Routes().Protect("GET example.com/items", h),
		"nil handler": rs.Routes().Protect("GET /items", nil),
		"nil option":  rs.Routes().Protect("GET /items", h, nil),
		"duplicate":   rs.Routes().Protect("GET /items", h).Protect("GET /items", h),
		"zero factor": rs.Routes().Protect("GET /items", h, egauth.RequireFactor(principal.Factor{})),
	} {
		_, err := rt.Build()
		require.Error(t, err, name)
	}
	_, err := (&egauth.APIRoutes[gateClaims]{}).Build()
	require.Error(t, err, "a zero APIRoutes")
}

func TestResourceServerCloseIsIdempotentAndStopsBuild(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	rs := w.server()
	s := &seen{}
	h := protectedItems(rs, s)
	tok := w.mint("nina@example.com", rsAudience)
	require.NoError(t, rs.Close())
	require.NoError(t, rs.Close())
	_, err := rs.Routes().Build()
	require.ErrorIs(t, err, egauth.ErrClosed)
	require.Equal(t, http.StatusOK, w.call(h, http.MethodGet, "/items", tok).Code, "a built handler keeps serving, reading the store")
}

func TestResourceServerRejectsTheWrongDeployment(t *testing.T) {
	w := newRSWorld(t)
	t.Run("audience the Auth does not publish", func(t *testing.T) {
		_, err := egauth.NewLoopbackResourceServer[gateClaims](withAudience(w.config(), "http://localhost:9099"), w.clk.Library())
		requireField(t, err, "Audience")
	})
	t.Run("another claims type", func(t *testing.T) {
		cfg := w.config()
		_, err := egauth.NewLoopbackResourceServer[struct{}](cfg, w.clk.Library())
		requireField(t, err, "AuthOrigin")
		require.Contains(t, err.Error(), "claims type")
	})
	t.Run("HS256 publishes no key and no audience", func(t *testing.T) {
		hw := newRSWorld(t, func(c *egauth.Config[gateClaims]) {
			c.Sessions = egauth.JWT(egauth.StaticKeys(hsSigner(t, "hs-1")))
			c.Audiences = nil
		})
		_, err := egauth.NewLoopbackResourceServer[gateClaims](hw.config(), hw.clk.Library())
		requireField(t, err, "Audience")
		require.Contains(t, err.Error(), "publishes no JWKS")
	})
	t.Run("stateful sessions", func(t *testing.T) {
		sw := newRSWorld(t, stateful)
		_, err := egauth.NewLoopbackResourceServer[gateClaims](sw.config(), sw.clk.Library())
		requireField(t, err, "Audience")
		require.Contains(t, err.Error(), "publishes no JWKS")
	})
	t.Run("an unreachable origin", func(t *testing.T) {
		cfg := w.config()
		cfg.AuthOrigin = "http://127.0.0.1:1"
		_, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
		requireField(t, err, "AuthOrigin")
	})
	t.Run("the SSRF guard applies without the test allowance", func(t *testing.T) {
		_, err := egauth.NewResourceServer[gateClaims](w.config())
		requireField(t, err, "AuthOrigin")
	})
}

func withAudience(c egauth.ResourceConfig, aud string) egauth.ResourceConfig {
	c.Audience = aud
	return c
}

func TestResourceServerConfigErrorsNameTheirField(t *testing.T) {
	w := newRSWorld(t)
	st := memstore.New(testKEK(t))
	mods := map[string]struct {
		mut   func(*egauth.ResourceConfig)
		field string
	}{
		"no revocation":      {func(c *egauth.ResourceConfig) { c.Revocation = nil }, "Revocation"},
		"empty storage":      {func(c *egauth.ResourceConfig) { c.Revocation = egauth.FromStorage(egauth.Storage{}) }, "Revocation"},
		"no proxy":           {func(c *egauth.ResourceConfig) { c.Proxy = nil }, "Proxy"},
		"no origin":          {func(c *egauth.ResourceConfig) { c.AuthOrigin = "" }, "AuthOrigin"},
		"origin with path":   {func(c *egauth.ResourceConfig) { c.AuthOrigin = "https://auth.example.com/x" }, "AuthOrigin"},
		"tenant origin":      {func(c *egauth.ResourceConfig) { c.AuthOrigin = "https://{tenant}.example.com" }, "AuthOrigin"},
		"no audience":        {func(c *egauth.ResourceConfig) { c.Audience = "" }, "Audience"},
		"audience with path": {func(c *egauth.ResourceConfig) { c.Audience = "https://api.example.com/v1" }, "Audience"},
		"blank ack": {func(c *egauth.ResourceConfig) {
			c.Revocation = nil
			c.Insecure.RevocationLagUpToTTL = egauth.Acknowledge("  ")
		}, "Insecure.RevocationLagUpToTTL"},
		"opt-out and source": {func(c *egauth.ResourceConfig) {
			c.Revocation = egauth.FromStorage(st)
			c.Insecure.RevocationLagUpToTTL = egauth.Acknowledge("both")
		}, "Insecure.RevocationLagUpToTTL"},
		"bad proxy": {func(c *egauth.ResourceConfig) { c.Proxy = egauth.TrustedProxies(netip.MustParsePrefix("0.0.0.0/0")) }, "Proxy"},
	}
	for name, m := range mods {
		t.Run(name, func(t *testing.T) {
			cfg := w.config()
			m.mut(&cfg)
			_, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
			requireField(t, err, m.field)
		})
	}
}

func TestResourceServerDefaultsItsEventSink(t *testing.T) {
	w := newRSWorld(t)
	cfg := w.config()
	cfg.Events = nil
	rs, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
	require.NoError(t, err)
	require.NoError(t, rs.Close())
	r, errs := egauth.ResolveResource(cfg)
	require.Empty(t, errs)
	require.True(t, r.Defaulted("Events"))
}

func TestResourceServerRefusesATenantTheAuthDoesNotServe(t *testing.T) {
	w := newRSWorld(t)
	cfg := w.config()
	cfg.Tenant = "acme"
	_, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
	requireField(t, err, "Tenant")
	w.seedUser("nina@example.com", false)
	tok := w.mint("nina@example.com", rsAudience)
	require.Equal(t, http.StatusOK, w.call(protectedItems(w.server(), &seen{}), http.MethodGet, "/items", tok).Code)
}

func TestResourceServerRejectsAnInvalidTenant(t *testing.T) {
	w := newRSWorld(t)
	cfg := w.config()
	cfg.Tenant = "not a tenant!"
	_, err := egauth.NewLoopbackResourceServer[gateClaims](cfg, w.clk.Library())
	requireField(t, err, "Tenant")
}

func TestResourceServerCanBeBuiltByAConsumerAgainstALoopbackAuth(t *testing.T) {
	w := newRSWorld(t)
	w.seedUser("nina@example.com", false)
	rs, err := egauthtest.NewResourceServer[gateClaims](w.config(), w.clk, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rs.Close() })
	tok := w.mint("nina@example.com", rsAudience)
	require.Equal(t, http.StatusOK, w.call(protectedItems(rs, &seen{}), http.MethodGet, "/items", tok).Code)
}
