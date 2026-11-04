package egauth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
)

const (
	spaOrigin     = "https://spa.example.com"
	devSPAOrigin  = "http://localhost:5173"
	devSibling    = "http://localhost:3000"
	spaLoginBody  = `{"identifier":"spa@example.com","password":"` + gatePassword + `"}`
	headerACAO    = "Access-Control-Allow-Origin"
	headerACAC    = "Access-Control-Allow-Credentials"
	headerACAM    = "Access-Control-Allow-Methods"
	headerACAH    = "Access-Control-Allow-Headers"
	headerACEH    = "Access-Control-Expose-Headers"
	headerACRM    = "Access-Control-Request-Method"
	headerACRH    = "Access-Control-Request-Headers"
	headerVary    = "Vary"
	headerSite    = "Sec-Fetch-Site"
	headerMode    = "Sec-Fetch-Mode"
	headerOriginH = "Origin"
)

func withSPA(c *egauth.Config[struct{}]) {
	c.SPAOrigins = []string{spaOrigin}
	c.Modules.Passkey.RPID = "example.com"
}

func TestConfigSPAOrigins(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*egauth.Config[struct{}])
		field string
	}{
		{"cross-site", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{"https://spa.example.net"}
		}, "SPAOrigins[0]"},
		{"tenant label", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{"https://{tenant}.example.com"}
		}, "SPAOrigins[0]"},
		{"equals the public origin", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{c.PublicOrigin}
		}, "SPAOrigins[0]"},
		{"equals an extra origin", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{c.ExtraOrigins[0]}
		}, "SPAOrigins[0]"},
		{"http off loopback", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{"http://spa.example.com"}
		}, "SPAOrigins[0]"},
		{"scheme differs from the public origin", func(c *egauth.Config[struct{}]) {
			c.PublicOrigin, c.ExtraOrigins, c.Audiences = "http://localhost:8080", nil, nil
			c.SPAOrigins = []string{"https://localhost:5173"}
		}, "SPAOrigins[0]"},
		{"duplicate", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{spaOrigin, spaOrigin}
		}, "SPAOrigins[1]"},
		{"audience equals a SPA origin", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.SPAOrigins = []string{c.Audiences[0]}
		}, "Audiences[0]"},
		{"outside the default passkey relying party id", func(c *egauth.Config[struct{}]) {
			c.SPAOrigins = []string{spaOrigin}
		}, "SPAOrigins[0]"},
		{"parent of the public origin", func(c *egauth.Config[struct{}]) {
			c.Modules.Passkey = nil
			c.SPAOrigins = []string{"https://example.com"}
		}, "SPAOrigins[0]"},
		{"shared cookie domain", func(c *egauth.Config[struct{}]) {
			withSPA(c)
			c.Modules.Passkey = nil
			c.Insecure.SharedCookieDomain = &egauth.SharedCookieDomain{
				Domain: "example.com",
				Ack:    egauth.Acknowledge("test: a shared cookie would reach the SPA"),
			}
		}, "SPAOrigins"},
		{"multi-tenant tenancy", func(c *egauth.Config[struct{}]) {
			c.Modules.Passkey = nil
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin, c.ExtraOrigins, c.Audiences = "https://{tenant}.example.com", nil, nil
			c.SPAOrigins = []string{spaOrigin}
		}, "SPAOrigins"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), tc.field)
		})
	}
	t.Run("without passkeys", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Modules.Passkey = nil
		cfg.SPAOrigins = []string{spaOrigin}
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("with a covering relying party id", func(t *testing.T) {
		cfg := fullConfig(t)
		withSPA(&cfg)
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("loopback development server", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.PublicOrigin, cfg.ExtraOrigins, cfg.Audiences = "http://localhost:8080", nil, nil
		cfg.SPAOrigins = []string{devSPAOrigin}
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("pages on a SPA origin", func(t *testing.T) {
		cfg := fullConfig(t)
		withSPA(&cfg)
		cfg.Pages.AfterLogin = spaOrigin + "/home"
		cfg.Pages.MFA = spaOrigin + "/mfa"
		cfg.Pages.Reauth = spaOrigin + "/reauth"
		cfg.Pages.Error = spaOrigin + "/error"
		cfg.Pages.MagicLink = spaOrigin + "/magic"
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("page on an undeclared sibling", func(t *testing.T) {
		cfg := fullConfig(t)
		withSPA(&cfg)
		cfg.Pages.AfterLogin = "https://other.example.com/home"
		requireField(t, newErr(t, cfg), "Pages.AfterLogin")
	})
}

func TestConfigPasskeyRPID(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*egauth.Config[struct{}])
	}{
		{"does not cover the public origin", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.RPID = "other.example.org" }},
		{"narrower than the public origin", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.RPID = "x.app.example.com" }},
		{"public suffix", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.RPID = "com" }},
		{"not lower case", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.RPID = "Example.com" }},
		{"an origin, not a domain", func(c *egauth.Config[struct{}]) { c.Modules.Passkey.RPID = "https://example.com" }},
		{"an IP address", func(c *egauth.Config[struct{}]) {
			c.PublicOrigin, c.ExtraOrigins = "https://192.0.2.10", nil
			c.Modules.Passkey.RPID = "192.0.2.10"
		}},
		{"under subdomain tenancy", func(c *egauth.Config[struct{}]) {
			c.Tenancy = egauth.TenantBySubdomain()
			c.PublicOrigin, c.ExtraOrigins = "https://{tenant}.example.com", nil
			c.Modules.Passkey.RPID = "example.com"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mut(&cfg)
			requireField(t, newErr(t, cfg), "Modules.Passkey.RPID")
		})
	}
	t.Run("parent domain of every origin", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Modules.Passkey.RPID = "example.com"
		require.NoError(t, newErr(t, cfg))
	})
	t.Run("equal to the public origin host", func(t *testing.T) {
		cfg := fullConfig(t)
		cfg.Modules.Passkey.RPID = "app.example.com"
		require.NoError(t, newErr(t, cfg))
	})
}

func spaWorld(t *testing.T) (*gateWorld, http.Handler, *seen) {
	t.Helper()
	w := newGateWorld(t, func(c *egauth.Config[gateClaims]) { c.SPAOrigins = []string{devSPAOrigin} })
	w.seedUser("spa@example.com", false)
	s, mc := &seen{}, &seen{}
	return w, gateRoutes(w, s, mc), s
}

func fromSite(origin, site string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set(headerOriginH, origin)
		r.Header.Set(headerSite, site)
		r.Header.Set(headerMode, "cors")
	}
}

func spaLogin(w *gateWorld, h http.Handler, mut ...func(*http.Request)) (*httptest.ResponseRecorder, credentials) {
	req := httptest.NewRequest(http.MethodPost, gateOrigin+"/auth/login", strings.NewReader(spaLoginBody))
	req.Header.Set("Content-Type", "application/json")
	for _, m := range mut {
		m(req)
	}
	rec := w.serve(h, req)
	return rec, credentials{cookies: rec.Result().Cookies(), code: rec.Code}
}

func requireCORS(t *testing.T, rec *httptest.ResponseRecorder, origin string) {
	t.Helper()
	require.Equal(t, origin, rec.Header().Get(headerACAO))
	require.Equal(t, "true", rec.Header().Get(headerACAC))
	require.Contains(t, rec.Header().Values(headerVary), "Origin")
}

func requireNoCORS(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Empty(t, rec.Header().Get(headerACAO))
	require.Empty(t, rec.Header().Get(headerACAC))
}

func TestSPALoginAndSessionFromASameSiteOrigin(t *testing.T) {
	w, h, s := spaWorld(t)

	rec, c := spaLogin(w, h, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	requireCORS(t, rec, devSPAOrigin)
	require.NotEmpty(t, c.cookieHeader(), "the SPA gets the session as cookies")
	require.Equal(t, "Retry-After", rec.Header().Get(headerACEH), "no token header is ever exposed to a SPA")

	rec = w.request(h, http.MethodGet, "/account", c, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	requireCORS(t, rec, devSPAOrigin)
	require.Equal(t, egauth.Session, s.last(t).Kind())

	rec = w.request(h, http.MethodPost, "/account", c, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	requireCORS(t, rec, devSPAOrigin)

	rec = w.request(h, http.MethodGet, "/auth/session", c, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	requireCORS(t, rec, devSPAOrigin)
}

func TestSPARefusalsCarryCORSSoTheSPACanReadThem(t *testing.T) {
	w, h, _ := spaWorld(t)
	rec := w.request(h, http.MethodGet, "/account", credentials{}, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireCORS(t, rec, devSPAOrigin)
}

func TestSPAUndeclaredSameSiteOriginIsRefused(t *testing.T) {
	w, h, _ := spaWorld(t)
	rec, _ := spaLogin(w, h, fromSite(devSibling, "same-site"))
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	requireNoCORS(t, rec)

	_, c := spaLogin(w, h, fromSite(devSPAOrigin, "same-site"))
	rec = w.request(h, http.MethodPost, "/account", c, fromSite(devSibling, "same-site"))
	require.Equal(t, http.StatusForbidden, rec.Code)
	requireNoCORS(t, rec)

	rec = w.request(h, http.MethodPost, "/account", c, fromSite(devSPAOrigin, "cross-site"))
	require.Equal(t, http.StatusForbidden, rec.Code, "cross-site stays refused, even from a SPA origin")
}

func TestSPASameSiteIsRefusedWithoutSPAOrigins(t *testing.T) {
	w := newGateWorld(t)
	w.seedUser("spa@example.com", false)
	h := gateRoutes(w, &seen{}, &seen{})
	rec, _ := spaLogin(w, h, fromSite(devSPAOrigin, "same-site"))
	require.Equal(t, http.StatusForbidden, rec.Code)
	requireNoCORS(t, rec)
	require.Empty(t, rec.Header().Values(headerVary), "a deployment without SPA origins answers exactly as before")
}

func preflight(w *gateWorld, h http.Handler, origin, path, method, headers string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodOptions, gateOrigin+path, nil)
	req.Header.Set(headerOriginH, origin)
	req.Header.Set(headerSite, "same-site")
	req.Header.Set(headerMode, "cors")
	req.Header.Set(headerACRM, method)
	if headers != "" {
		req.Header.Set(headerACRH, headers)
	}
	return w.serve(h, req)
}

func TestSPAPreflight(t *testing.T) {
	w, h, s := spaWorld(t)

	rec := preflight(w, h, devSPAOrigin, "/auth/login", http.MethodPost, "content-type")
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	requireCORS(t, rec, devSPAOrigin)
	require.Equal(t, http.MethodPost, rec.Header().Get(headerACAM))
	require.Contains(t, strings.ToLower(rec.Header().Get(headerACAH)), "content-type")
	require.NotContains(t, strings.ToLower(rec.Header().Get(headerACAH)), "authorization")
	require.NotContains(t, strings.ToLower(rec.Header().Get(headerACAH)), "x-egauth")

	n := s.count()
	rec = preflight(w, h, devSPAOrigin, "/account", http.MethodPost, "content-type")
	require.Equal(t, http.StatusNoContent, rec.Code)
	requireCORS(t, rec, devSPAOrigin)
	require.Equal(t, n, s.count(), "a preflight never reaches the application handler")

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unknown path":             preflight(w, h, devSPAOrigin, "/nope", http.MethodGet, ""),
		"method not served":        preflight(w, h, devSPAOrigin, "/account", http.MethodDelete, ""),
		"undeclared origin":        preflight(w, h, devSibling, "/auth/login", http.MethodPost, "content-type"),
		"invalid requested method": preflight(w, h, devSPAOrigin, "/auth/login", "PO ST", ""),
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, http.StatusNotFound, rec.Code)
			requireNoCORS(t, rec)
		})
	}
}

func TestSPACannotReadCredentialRoutes(t *testing.T) {
	w, h, _ := spaWorld(t)
	_, c := spaLogin(w, h, fromSite(devSPAOrigin, "same-site"))

	for _, path := range []string{
		egauth.PathResourceToken,
		egauth.PathMFATOTPEnroll,
		egauth.PathMFATOTPConfirm,
		egauth.PathMFARecoveryCodesRegenerate,
	} {
		t.Run(path, func(t *testing.T) {
			rec := w.request(h, http.MethodPost, "/auth"+path, c, fromSite(devSPAOrigin, "same-site"))
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			requireNoCORS(t, rec)

			rec = preflight(w, h, devSPAOrigin, "/auth"+path, http.MethodPost, "content-type")
			require.NotEqual(t, http.StatusNoContent, rec.Code)
			requireNoCORS(t, rec)
		})
	}
}
