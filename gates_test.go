package egauth_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/sessions"
)

func gateRoutes(w *gateWorld, s *seen, mustChange *seen) http.Handler {
	return w.build(w.a.Routes().
		Protect("GET /account", s.handler).
		Protect("POST /account", s.handler).
		Protect("GET /change", mustChange.handler, egauth.AcceptMustChange()).
		Protect("GET /admin", s.handler, egauth.RequireAnyRole("admin")).
		Protect("GET /mfa-only", s.handler, egauth.RequireMFA()).
		Optional("GET /home", s.handler).
		Optional("POST /home", s.handler).
		Optional("GET /home-admin", s.handler, egauth.RequireAnyRole("admin")).
		Optional("GET /home-change", mustChange.handler, egauth.AcceptMustChange()))
}

func TestGatesProtectServesAnEstablishedSessionOnBothBackends(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newGateWorld(t, opt)
			sub := w.seedUser("alice@example.com", false)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)
			for _, bearer := range []bool{false, true} {
				c := w.login(h, "alice@example.com", bearer)
				require.Equal(t, http.StatusOK, c.code, c.body)
				rec := w.request(h, http.MethodGet, "/account", c)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				p := s.last(t)
				require.Equal(t, egauth.Session, p.Kind())
				require.Equal(t, sub, p.Subject())
				require.Equal(t, []string{"user"}, p.Claims().Roles)
				require.Equal(t, "pro", p.Claims().Custom.Plan)
				require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

				rec = w.request(h, http.MethodGet, "/home", c)
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, egauth.Session, s.last(t).Kind())

				rec = w.request(h, http.MethodGet, "/admin", c)
				require.Equal(t, http.StatusForbidden, rec.Code)
				rec = w.request(h, http.MethodGet, "/home-admin", c)
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, egauth.Anonymous, s.last(t).Kind())
				rec = w.request(h, http.MethodGet, "/mfa-only", c)
				require.Equal(t, http.StatusForbidden, rec.Code)
			}
		})
	}
}

func TestGatesHandlerSeesThePrincipalInTheRequestSlot(t *testing.T) {
	w := newGateWorld(t)
	w.seedUser("alice@example.com", false)
	var inRequest, typed bool
	h := w.build(w.a.Routes().Protect("GET /account", func(rw http.ResponseWriter, r *http.Request, p egauth.Principal[gateClaims]) {
		inRequest = principalctx.InRequest(r.Context())
		got, ok := principalctx.Get[egauth.Principal[gateClaims]](r.Context())
		typed = ok && got.Subject() == p.Subject()
		rw.WriteHeader(http.StatusOK)
	}))
	c := w.login(h, "alice@example.com", false)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)
	require.True(t, inRequest)
	require.True(t, typed)
}

func TestGatesMFAFlowIsNeverASession(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newGateWorld(t, opt)
			sub := w.seedUser("bob@example.com", false)
			w.enrollTOTP(sub)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)

			c := w.login(h, "bob@example.com", false)
			require.Equal(t, http.StatusOK, c.code, c.body)
			require.Equal(t, "mfa_required", c.body["state"])
			require.NotEmpty(t, c.cookieHeader(), "the flow cookie is the only credential")
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", c).Code)
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/change", c).Code)
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/auth/session", c).Code)
			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", c).Code)
			require.Equal(t, egauth.Anonymous, s.last(t).Kind())
			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home-change", c).Code)
			require.Equal(t, egauth.Anonymous, mc.last(t).Kind())

			b := w.login(h, "bob@example.com", true)
			require.Equal(t, "mfa_required", b.body["state"])
			handle, _ := b.body["flow"].(string)
			require.NotEmpty(t, handle)
			flow := credentials{bearer: handle}
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", flow).Code)
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/home", flow).Code)
			require.Equal(t, 1, s.count())
		})
	}
}

func TestGatesMustChangeIsRefusedUnlessAccepted(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newGateWorld(t, opt)
			w.seedUser("carol@example.com", true)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)
			c := w.login(h, "carol@example.com", false)
			require.Equal(t, http.StatusOK, c.code, c.body)

			rec := w.request(h, http.MethodGet, "/account", c)
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "password_change_required")
			require.False(t, clearsSessionCookies(rec))
			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/change", c).Code)
			require.Equal(t, egauth.Session, mc.last(t).Kind())

			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", c).Code)
			require.Equal(t, egauth.Anonymous, s.last(t).Kind())
			require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home-change", c).Code)
			require.Equal(t, egauth.Session, mc.last(t).Kind())
		})
	}
}

func TestGatesRevokedSessionIsRefusedAndItsCookiesCleared(t *testing.T) {
	for name, opt := range map[string]func(*egauth.Config[gateClaims]){"jwt": func(*egauth.Config[gateClaims]) {}, "stateful": stateful} {
		t.Run(name, func(t *testing.T) {
			w := newGateWorld(t, opt)
			sub := w.seedUser("dave@example.com", false)
			s, mc := &seen{}, &seen{}
			h := gateRoutes(w, s, mc)
			c := w.login(h, "dave@example.com", false)
			b := w.login(h, "dave@example.com", true)
			w.disable(sub, true)

			rec := w.request(h, http.MethodGet, "/account", c)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.True(t, clearsSessionCookies(rec))
			rec = w.request(h, http.MethodGet, "/home", c)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, egauth.Anonymous, s.last(t).Kind())
			require.True(t, clearsSessionCookies(rec))

			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", b).Code)
			require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/home", b).Code)
		})
	}
}

func TestGatesInvalidCredentials(t *testing.T) {
	w := newGateWorld(t)
	s, mc := &seen{}, &seen{}
	h := gateRoutes(w, s, mc)
	garbage := credentials{cookies: []*http.Cookie{{Name: "access_token", Value: "garbage"}, {Name: "refresh_token", Value: "garbage"}}}

	rec := w.request(h, http.MethodGet, "/account", garbage)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.True(t, clearsSessionCookies(rec))
	rec = w.request(h, http.MethodGet, "/home", garbage)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, clearsSessionCookies(rec))
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())

	bad := credentials{bearer: "not-a-token"}
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", bad).Code)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/home", bad).Code)

	rec = w.request(h, http.MethodGet, "/account", credentials{})
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, clearsSessionCookies(rec))
	basic := func(r *http.Request) { r.SetBasicAuth("staging", "proxy") }
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", credentials{}, basic).Code,
		"a non-Bearer Authorization header, such as a staging proxy's, is no session credential")
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", credentials{}, basic).Code)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", credentials{}).Code)
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())
}

func TestGatesCSRF(t *testing.T) {
	w := newGateWorld(t)
	w.seedUser("erin@example.com", false)
	s, mc := &seen{}, &seen{}
	h := gateRoutes(w, s, mc)
	c := w.login(h, "erin@example.com", false)
	evil := func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }
	noOrigin := func(r *http.Request) { r.Header.Del("Origin") }
	crossFetch := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Sec-Fetch-Mode", "cors")
	}
	navigate := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
	}

	require.Equal(t, http.StatusOK, w.request(h, http.MethodPost, "/account", c).Code)
	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodPost, "/account", c, evil).Code)
	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodPost, "/account", c, noOrigin).Code)
	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodPost, "/home", c, evil).Code)
	require.Equal(t, http.StatusForbidden, w.request(h, http.MethodGet, "/account", c, crossFetch).Code)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c, navigate).Code)
	n := s.count()
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", c, crossFetch).Code)
	require.Equal(t, n+1, s.count())
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())

	b := w.login(h, "erin@example.com", true)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodPost, "/account", b, evil).Code)
}

func TestGatesTenantCrossCheck(t *testing.T) {
	w := newGateWorld(t, perRequestTenancy)
	w.tenant = "acme"
	w.seedUser("frank@example.com", false)
	s, mc := &seen{}, &seen{}
	h := gateRoutes(w, s, mc)
	c := w.login(h, "frank@example.com", false)
	require.Equal(t, http.StatusOK, c.code, c.body)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)

	other := func(r *http.Request) { r.Header.Set(gateTenantHdr, "globex") }
	rec := w.request(h, http.MethodGet, "/account", c, other)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, rec.Header().Values("Set-Cookie"))
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", c, other).Code)
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())

	none := func(r *http.Request) { r.Header.Set(gateTenantHdr, "Not A Tenant!") }
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", c, none).Code)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/home", c, none).Code)
}

func TestGatesOptionalPresentsAnAPIKeyAsAnonymous(t *testing.T) {
	w := newGateWorld(t)
	sub := w.seedUser("gina@example.com", false)
	s, mc := &seen{}, &seen{}
	h := gateRoutes(w, s, mc)
	key := w.createAPIKey(sub, "service", apiKeyGrant{Scopes: []string{"items:read"}})
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/home", credentials{bearer: key}).Code)
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", credentials{bearer: key}).Code)
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/auth/session", credentials{bearer: key}).Code)
}

type flakySessions struct {
	sessions.Store
	fail *atomic.Bool
}

func (f flakySessions) Get(ctx context.Context, t principal.TenantID, hash []byte) (sessions.Record, error) {
	if f.fail.Load() {
		return sessions.Record{}, errors.New("sessions store is down")
	}
	return f.Store.Get(ctx, t, hash)
}

func TestGatesAnOutageIs503OnProtectAndAnonymousOnOptional(t *testing.T) {
	down := &atomic.Bool{}
	w := newGateWorld(t, stateful, func(c *egauth.Config[gateClaims]) {
		c.Storage.Sessions = flakySessions{Store: c.Storage.Sessions, fail: down}
	})
	w.seedUser("quinn@example.com", false)
	s, mc := &seen{}, &seen{}
	h := gateRoutes(w, s, mc)
	c := w.login(h, "quinn@example.com", false)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)

	down.Store(true)
	rec := w.request(h, http.MethodGet, "/account", c)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.False(t, clearsSessionCookies(rec), "an outage never signs the user out")
	rec = w.request(h, http.MethodGet, "/home", c)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, egauth.Anonymous, s.last(t).Kind())
	require.False(t, clearsSessionCookies(rec))

	down.Store(false)
	require.Equal(t, http.StatusOK, w.request(h, http.MethodGet, "/account", c).Code)
	require.Equal(t, egauth.Session, s.last(t).Kind())
}
