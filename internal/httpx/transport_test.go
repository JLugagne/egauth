package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/limiter"
)

func TestNativeLogoutWithBearerAuthorizationSelectsBearer(t *testing.T) {
	logout, ok := routes.MetaFor(routes.Logout)
	if !ok {
		t.Fatal("no /logout meta")
	}
	cases := []struct {
		name      string
		allowed   httpx.Transports
		headers   map[string]string
		status    int
		transport core.Transport
	}{
		{"native bearer client", httpx.CookiesAndBearer, map[string]string{"Authorization": "Bearer native-access-token"}, http.StatusOK, core.TransportBearer},
		{"bearer only deployment", httpx.BearerOnly, map[string]string{"Authorization": "Bearer native-access-token"}, http.StatusOK, core.TransportBearer},
		{"bearer header with a cookie", httpx.CookiesAndBearer, map[string]string{"Authorization": "Bearer native-access-token", "Cookie": "__Host-session=x"}, http.StatusForbidden, 0},
		{"empty bearer credential", httpx.CookiesAndBearer, map[string]string{"Authorization": "Bearer "}, http.StatusForbidden, 0},
		{"basic credential", httpx.CookiesAndBearer, map[string]string{"Authorization": "Basic eDp5"}, http.StatusForbidden, 0},
		{"cookies only deployment", httpx.CookiesOnly, map[string]string{"Authorization": "Bearer native-access-token"}, http.StatusForbidden, 0},
		{"no credential", httpx.CookiesAndBearer, nil, http.StatusForbidden, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.set.Transports = tc.allowed
			var got core.Transport
			h := w.handler(t, logout, func(rw http.ResponseWriter, r *httpx.Request) {
				got = r.Transport()
				r.Respond(rw, httpx.Response{})
			})
			r := post(``, "")
			r.Header.Del("Origin")
			r.Header.Del("Sec-Fetch-Site")
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			resp := serve(h, r)
			if resp.Code != tc.status {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
			if tc.status == http.StatusForbidden && errorCode(t, resp) != "cross_site_request" {
				t.Fatalf("error %s", resp.Body)
			}
			if got != tc.transport {
				t.Fatalf("transport %v want %v", got, tc.transport)
			}
		})
	}
}

func TestBearerAuthorizationDoesNotSelectBearerOnLoginTypeEndpoints(t *testing.T) {
	for _, p := range []string{routes.Login, routes.Register, routes.MagicLink, routes.PasswordReset} {
		m, ok := routes.MetaFor(p)
		if !ok {
			t.Fatalf("no meta for %s", p)
		}
		w := newWorld(t)
		h := w.handler(t, m, nil)
		r := post(`{}`, "application/json")
		r.Header.Del("Origin")
		r.Header.Del("Sec-Fetch-Site")
		r.Header.Set("Authorization", "Bearer x")
		if resp := serve(h, r); resp.Code != http.StatusForbidden || slices.Contains(w.rec.got(), "endpoint") {
			t.Fatalf("%s: login CSRF must stay closed without X-Egauth-Transport: %d", p, resp.Code)
		}
	}
}

func TestSafeMethodBodyIsDiscarded(t *testing.T) {
	w := newWorld(t)
	meta := httpx.Meta{BodyCap: httpx.FormBodyCap}
	var read []byte
	h := w.handler(t, meta, func(rw http.ResponseWriter, r *httpx.Request) {
		read, _ = io.ReadAll(r.HTTP().Body)
		r.Respond(rw, httpx.Response{})
	})
	req := httptest.NewRequest(http.MethodGet, origin+"/auth/session", strings.NewReader(`{"password":"x"}`))
	req.RemoteAddr = "198.51.100.7:1"
	if resp := serve(h, req); resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if len(read) != 0 {
		t.Fatalf("the endpoint read %d body bytes of a safe request", len(read))
	}
}

func TestBearerChannelCarryingACookieSessionIsRefused(t *testing.T) {
	w := newWorld(t)
	w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, Transport: core.TransportCookies})
	w.auth.setCookie = "__Host-access_token=rotated"
	meta := httpx.Meta{Authenticated: true, Mutation: true, SetsCookies: true, BodyCap: httpx.FormBodyCap, ClientLimit: limiter.LoginClient}
	h := w.handler(t, meta, nil)
	r := post(`{}`, "application/json")
	r.Header.Set("Origin", "https://evil.example.org")
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Authorization", "Bearer x")
	resp := serve(h, r)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if c := resp.Header().Values("Set-Cookie"); len(c) != 0 {
		t.Fatalf("a refused request must not carry rotated cookies: %v", c)
	}
	if want := []string{"tenant", "limit:login_client", "resume"}; !slices.Equal(w.rec.got(), want) {
		t.Fatalf("order %v want %v", w.rec.got(), want)
	}
}

func TestCookieCarryingAuthenticatedRequestIsCSRFCheckedBeforeLimitAndResume(t *testing.T) {
	w := newWorld(t)
	meta := httpx.Meta{Authenticated: true, Mutation: true, SetsCookies: true, BodyCap: httpx.FormBodyCap, ClientLimit: limiter.LoginClient}
	h := w.handler(t, meta, nil)
	r := post(`{}`, "application/json")
	r.Header.Set("Origin", "https://evil.example.org")
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Authorization", "Bearer x")
	r.Header.Set("Cookie", "__Host-session=x")
	resp := serve(h, r)
	if resp.Code != http.StatusForbidden || errorCode(t, resp) != "cross_site_request" {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if want := []string{"tenant"}; !slices.Equal(w.rec.got(), want) {
		t.Fatalf("order %v want %v", w.rec.got(), want)
	}
}
