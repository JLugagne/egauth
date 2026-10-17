package httpx_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/limiter"
)

func TestPreambleRunsEveryStepInOrder(t *testing.T) {
	w := newWorld(t)
	w.auth.attrs = attrs(core.ForTestAttrs{
		Subject: subject(acme), Factors: []core.Factor{core.FactorPassword, core.FactorTOTP},
		PrimaryAt: start, SecondAt: start,
	})
	w.enr.required = true
	meta := sensitiveMeta()
	meta.IdentifierKeyed, meta.IdentifierLimit = true, limiter.LoginIdentifier
	h := w.handler(t, meta, nil)
	r := post(`{"identifier":"A@Example.com","captcha_token":"cap"}`, "application/json")
	r.Header.Set("Cookie", "__Host-session=x")
	resp := serve(h, r)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	want := []string{"tenant", "limit:login_client", "limit:login_identifier", "resume", "enrollment", "hook", "endpoint"}
	if got := w.rec.got(); !slices.Equal(got, want) {
		t.Fatalf("order %v want %v", got, want)
	}
	if w.hook.last.CaptchaToken() != "cap" || w.hook.last.Endpoint != "/login" || w.hook.last.Client.String() != "198.51.100.7" {
		t.Fatalf("hook call %+v", w.hook.last)
	}
	if got := resp.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
}

func TestTenantFailureStopsBeforeTheBodyIsRead(t *testing.T) {
	for name, set := range map[string]func(*fakeTenants){
		"resolver error": func(f *fakeTenants) { f.err = errors.New("no tenant") },
		"zero answer":    func(f *fakeTenants) { f.t = core.TenantID{} },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			set(w.tenant)
			h := w.handler(t, loginMeta(), nil)
			r := post(`{"identifier":"a@example.com"}`, "application/json")
			body := &trackingBody{r: r.Body}
			r.Body = body
			resp := serve(h, r)
			if resp.Code != http.StatusUnauthorized || errorCode(t, resp) != "unauthenticated" {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
			if body.read || !slices.Equal(w.rec.got(), []string{"tenant"}) {
				t.Fatalf("steps after tenant failure: read=%v %v", body.read, w.rec.got())
			}
		})
	}
}

func TestSingleTenantAcceptsZeroTenant(t *testing.T) {
	w := newWorld(t)
	o, err := csrfOrigins("https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	w.set.Origins = o
	env := w.env()
	env.Tenants = httpx.SingleTenant()
	p, err := httpx.NewPreamble(env, w.set)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Wrap("/login", loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) {
		r.Respond(rw, httpx.Response{})
	})
	if err != nil {
		t.Fatal(err)
	}
	r := post(`{}`, "application/json")
	r.Header.Set("Origin", "https://app.example.com")
	if resp := serve(h, r); resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
}

func TestBodyCapComesBeforeParseAndCSRF(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	big := `{"identifier":"` + strings.Repeat("a", int(httpx.FormBodyCap)) + `"}`
	r := post(big, "application/json")
	r.Header.Set("Origin", "https://evil.example")
	resp := serve(h, r)
	if resp.Code != http.StatusRequestEntityTooLarge || errorCode(t, resp) != "request_too_large" {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if !slices.Equal(w.rec.got(), []string{"tenant"}) {
		t.Fatalf("steps %v", w.rec.got())
	}
}

func TestWebAuthnCapAllowsLargerBodies(t *testing.T) {
	w := newWorld(t)
	meta := loginMeta()
	meta.BodyCap = httpx.WebAuthnBodyCap
	var raw []byte
	h := w.handler(t, meta, func(rw http.ResponseWriter, r *httpx.Request) {
		raw = r.WebAuthnBody()
		r.Respond(rw, httpx.Response{})
	})
	body := `{"handle":"h","response":"` + strings.Repeat("a", 32<<10) + `"}`
	if resp := serve(h, post(body, "application/json")); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	if string(raw) != body {
		t.Fatal("WebAuthn body not exposed verbatim")
	}
	over := `{"x":"` + strings.Repeat("a", int(httpx.WebAuthnBodyCap)) + `"}`
	if resp := serve(h, post(over, "application/json")); resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the WebAuthn cap: %d", resp.Code)
	}
}

func TestParseErrorsStopBeforeCSRFAndLimiter(t *testing.T) {
	cases := []struct {
		body, ct string
		status   int
	}{
		{`not json`, "application/json", http.StatusBadRequest},
		{`[1]`, "application/json", http.StatusBadRequest},
		{`{"identifier":"a","identifier":"b"}`, "application/json", http.StatusBadRequest},
		{`{"identifier":{"nested":1}}`, "application/json", http.StatusBadRequest},
		{`{"identifier":"a"} trailing`, "application/json", http.StatusBadRequest},
		{`identifier=a&identifier=b`, "application/x-www-form-urlencoded", http.StatusBadRequest},
		{`identifier=%zz`, "application/x-www-form-urlencoded", http.StatusBadRequest},
		{`--x`, "multipart/form-data; boundary=x", http.StatusUnsupportedMediaType},
		{`x`, "text/plain", http.StatusUnsupportedMediaType},
		{`x`, "", http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		w := newWorld(t)
		h := w.handler(t, loginMeta(), nil)
		resp := serve(h, post(tc.body, tc.ct))
		if resp.Code != tc.status {
			t.Errorf("%q %q: status %d want %d", tc.body, tc.ct, resp.Code, tc.status)
		}
		if !slices.Equal(w.rec.got(), []string{"tenant"}) {
			t.Errorf("%q: steps %v", tc.body, w.rec.got())
		}
	}
}

func TestCSRFRefusalStopsBeforeLimiter(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	r := post(`{"identifier":"a@example.com"}`, "application/json")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	resp := serve(h, r)
	if resp.Code != http.StatusForbidden || errorCode(t, resp) != "cross_site_request" {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if !slices.Equal(w.rec.got(), []string{"tenant"}) {
		t.Fatalf("steps %v", w.rec.got())
	}
}

func TestCSRFUsesTenantExpandedOrigin(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	ok := post(`{}`, "application/json")
	ok.Header.Set("Origin", "https://acme.example.com")
	if resp := serve(h, ok); resp.Code != http.StatusOK {
		t.Fatalf("own tenant origin: %d %s", resp.Code, resp.Body)
	}
	other := post(`{}`, "application/json")
	other.Header.Set("Origin", "https://other.example.com")
	if resp := serve(h, other); resp.Code != http.StatusForbidden {
		t.Fatalf("other tenant origin: %d", resp.Code)
	}
}

func TestNoOriginCheckSkipsOnlyCSRF(t *testing.T) {
	w := newWorld(t)
	w.set.Insecure.NoOriginCheck = true
	h := w.handler(t, loginMeta(), nil)
	r := post(`{}`, "application/json")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := serve(h, r); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	if !slices.Contains(w.rec.got(), "limit:login_client") {
		t.Fatal("rate limit must still apply")
	}
}

func TestRateLimitOnClientStopsBeforeIdentifierAndAuth(t *testing.T) {
	w := newWorld(t)
	w.lim.deny[limiter.LoginClient] = true
	w.lim.retry = 1500 * time.Millisecond
	h := w.handler(t, loginMeta(), nil)
	resp := serve(h, post(`{"identifier":"a@example.com"}`, "application/json"))
	if resp.Code != http.StatusTooManyRequests || resp.Header().Get("Retry-After") != "2" {
		t.Fatalf("status %d retry %q", resp.Code, resp.Header().Get("Retry-After"))
	}
	if !slices.Equal(w.rec.got(), []string{"tenant", "limit:login_client"}) {
		t.Fatalf("steps %v", w.rec.got())
	}
}

func TestIdentifierLimitUsesNormalisedTenantScopedKey(t *testing.T) {
	w := newWorld(t)
	w.lim.deny[limiter.LoginIdentifier] = true
	h := w.handler(t, loginMeta(), nil)
	r := post(`{"identifier":"  Victim@Example.COM "}`, "application/json")
	r.Header.Set("Origin", "https://acme.example.com")
	resp := serve(h, r)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", resp.Code)
	}
	if len(w.lim.keys) != 2 {
		t.Fatalf("keys %v", w.lim.keys)
	}
	client, ident := w.lim.keys[0], w.lim.keys[1]
	if client.Class != limiter.LoginClient || client.Value != "198.51.100.7" || !client.Tenant.IsZero() || !client.Valid() {
		t.Fatalf("client key %+v", client)
	}
	if ident.Class != limiter.LoginIdentifier || ident.Value != "email:victim@example.com" || ident.Tenant != acme || !ident.Valid() {
		t.Fatalf("identifier key %+v", ident)
	}
}

func TestIdentifierLimitSkipsAbsentOrInvalidIdentifier(t *testing.T) {
	for _, body := range []string{`{}`, `{"identifier":"no-at-sign"}`, `{"identifier":""}`} {
		w := newWorld(t)
		h := w.handler(t, loginMeta(), nil)
		if resp := serve(h, post(body, "application/json")); resp.Code != http.StatusOK {
			t.Fatalf("%s: %d", body, resp.Code)
		}
		if len(w.lim.keys) != 1 {
			t.Fatalf("%s: keys %v", body, w.lim.keys)
		}
	}
}

func TestLongIdentifierIsHashedIntoAValidKey(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	long := strings.Repeat("a", 300) + "@example.com"
	if resp := serve(h, post(`{"identifier":"`+long+`"}`, "application/json")); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	if k := w.lim.keys[1]; !k.Valid() || len(k.Value) != 64 {
		t.Fatalf("key %+v", k)
	}
}

func TestLimiterErrorFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.lim.err = errors.New("store down")
	h := w.handler(t, loginMeta(), nil)
	resp := serve(h, post(`{}`, "application/json"))
	if resp.Code != http.StatusServiceUnavailable || slices.Contains(w.rec.got(), "endpoint") {
		t.Fatalf("status %d steps %v", resp.Code, w.rec.got())
	}
}

func TestNoRateLimitSkipsLimiter(t *testing.T) {
	w := newWorld(t)
	w.set.Insecure.NoRateLimit = true
	env := w.env()
	env.Limiter = nil
	p, err := httpx.NewPreamble(env, w.set)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Wrap("/login", loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) { r.Respond(rw, httpx.Response{}) })
	if err != nil {
		t.Fatal(err)
	}
	if resp := serve(h, post(`{}`, "application/json")); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
}

func TestAuthenticationFailures(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*world)
		status int
		code   string
	}{
		{"invalid credential", func(w *world) { w.auth.err = errors.New("bad token") }, 401, "unauthenticated"},
		{"store unavailable", func(w *world) { w.auth.err = errors.Join(httpx.ErrUnavailable, errors.New("db")) }, 503, "unavailable"},
		{"other tenant's session", func(w *world) {
			other, _ := core.ParseTenantID("other")
			w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(other), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start})
		}, 401, "unauthenticated"},
		{"must change", func(w *world) {
			w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, MustChange: true})
		}, 403, "password_change_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.set(w)
			meta := sensitiveMeta()
			h := w.handler(t, meta, nil)
			resp := serve(h, post(`{}`, "application/json"))
			if resp.Code != tc.status || errorCode(t, resp) != tc.code {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
			got := w.rec.got()
			if slices.Contains(got, "enrollment") || slices.Contains(got, "hook") || slices.Contains(got, "endpoint") {
				t.Fatalf("steps after authentication failure %v", got)
			}
		})
	}
}

func TestAcceptsMustChangeLetsTheSessionThrough(t *testing.T) {
	w := newWorld(t)
	w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, MustChange: true})
	meta := sensitiveMeta()
	meta.AcceptsMustChange = true
	var gotSession bool
	h := w.handler(t, meta, func(rw http.ResponseWriter, r *httpx.Request) {
		_, gotSession = r.Session()
		r.Respond(rw, httpx.Response{})
	})
	if resp := serve(h, post(`{}`, "application/json")); resp.Code != http.StatusOK || !gotSession {
		t.Fatalf("status %d session %v", resp.Code, gotSession)
	}
}

func TestUnauthenticatedEndpointNeverResumes(t *testing.T) {
	w := newWorld(t)
	var gotSession bool
	h := w.handler(t, loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) {
		_, gotSession = r.Session()
		r.Respond(rw, httpx.Response{})
	})
	serve(h, post(`{}`, "application/json"))
	if gotSession || slices.Contains(w.rec.got(), "resume") {
		t.Fatal("an unauthenticated endpoint resumed a session")
	}
}

func TestSensitiveGate(t *testing.T) {
	s := subject(acme)
	pwd := []core.Factor{core.FactorPassword}
	mfa := []core.Factor{core.FactorPassword, core.FactorTOTP}
	cases := []struct {
		name     string
		attrs    core.SessionAttrs
		required bool
		enrErr   error
		noWindow bool
		status   int
	}{
		{"fresh single factor, not enrolled", attrs(core.ForTestAttrs{Subject: s, Factors: pwd, PrimaryAt: start}), false, nil, false, 200},
		{"fresh single factor, enrolled", attrs(core.ForTestAttrs{Subject: s, Factors: pwd, PrimaryAt: start}), true, nil, false, 403},
		{"fresh multi factor, enrolled", attrs(core.ForTestAttrs{Subject: s, Factors: mfa, PrimaryAt: start, SecondAt: start}), true, nil, false, 200},
		{"stale primary", attrs(core.ForTestAttrs{Subject: s, Factors: pwd, PrimaryAt: start.Add(-time.Hour)}), false, nil, false, 403},
		{"fresh password, stale second factor", attrs(core.ForTestAttrs{Subject: s, Factors: mfa, PrimaryAt: start, SecondAt: start.Add(-time.Hour)}), true, nil, false, 403},
		{"stale but NoReauthWindow", attrs(core.ForTestAttrs{Subject: s, Factors: pwd, PrimaryAt: start.Add(-time.Hour)}), false, nil, true, 200},
		{"NoReauthWindow keeps the MFA rule", attrs(core.ForTestAttrs{Subject: s, Factors: pwd, PrimaryAt: start}), true, nil, true, 403},
		{"enrollment read fails closed", attrs(core.ForTestAttrs{Subject: s, Factors: mfa, PrimaryAt: start, SecondAt: start}), false, errors.New("db"), false, 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.auth.attrs = tc.attrs
			w.enr.required, w.enr.err = tc.required, tc.enrErr
			w.set.Insecure.NoReauthWindow = tc.noWindow
			h := w.handler(t, sensitiveMeta(), nil)
			resp := serve(h, post(`{}`, "application/json"))
			if resp.Code != tc.status {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
			if tc.status == http.StatusForbidden && errorCode(t, resp) != "reauth_required" {
				t.Fatalf("code %s", resp.Body)
			}
			if tc.status != http.StatusOK && (slices.Contains(w.rec.got(), "hook") || slices.Contains(w.rec.got(), "endpoint")) {
				t.Fatalf("steps after sensitive refusal %v", w.rec.got())
			}
		})
	}
}

func TestHookRefusalStopsBeforeEndpoint(t *testing.T) {
	w := newWorld(t)
	w.hook.err = errors.New("captcha failed: secret detail")
	h := w.handler(t, loginMeta(), nil)
	resp := serve(h, post(`{}`, "application/json"))
	if resp.Code != http.StatusForbidden || errorCode(t, resp) != "request_rejected" {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if strings.Contains(resp.Body.String(), "secret detail") {
		t.Fatal("hook error text leaked to the client")
	}
	if slices.Contains(w.rec.got(), "endpoint") {
		t.Fatal("endpoint ran after the hook refused")
	}
}

func TestTransportSelection(t *testing.T) {
	cases := []struct {
		allowed httpx.Transports
		header  string
		want    core.Transport
	}{
		{httpx.CookiesAndBearer, "bearer", core.TransportBearer},
		{httpx.CookiesAndBearer, "BEARER", core.TransportBearer},
		{httpx.CookiesAndBearer, "", core.TransportCookies},
		{httpx.CookiesAndBearer, "cookies", core.TransportCookies},
		{httpx.CookiesOnly, "bearer", core.TransportCookies},
		{httpx.BearerOnly, "", core.TransportBearer},
	}
	for _, tc := range cases {
		w := newWorld(t)
		w.set.Transports = tc.allowed
		var got core.Transport
		h := w.handler(t, loginMeta(), func(rw http.ResponseWriter, r *httpx.Request) {
			got = r.Transport()
			r.Respond(rw, httpx.Response{})
		})
		r := post(`{}`, "application/json")
		if tc.header != "" {
			r.Header.Set("X-Egauth-Transport", tc.header)
		}
		serve(h, r)
		if got != tc.want {
			t.Errorf("%v %q: got %v want %v", tc.allowed, tc.header, got, tc.want)
		}
	}
	w := newWorld(t)
	w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, Transport: core.TransportBearer})
	var got core.Transport
	meta := sensitiveMeta()
	meta.Sensitive = false
	h := w.handler(t, meta, func(rw http.ResponseWriter, r *httpx.Request) {
		got = r.Transport()
		r.Respond(rw, httpx.Response{})
	})
	serve(h, post(`{}`, "application/json"))
	if got != core.TransportBearer {
		t.Fatalf("a resumed session must keep its sealed transport, got %v", got)
	}
}

func TestUnresolvableClientFailsClosed(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, loginMeta(), nil)
	r := post(`{}`, "application/json")
	r.RemoteAddr = "@"
	if resp := serve(h, r); resp.Code != http.StatusBadRequest || slices.Contains(w.rec.got(), "endpoint") {
		t.Fatalf("status %d", resp.Code)
	}
}

func TestBearerCSRFExemptionNeedsBearerTransport(t *testing.T) {
	cases := []struct {
		name    string
		allowed httpx.Transports
		h       map[string]string
		status  int
	}{
		{"cookies only with authorization bearer", httpx.CookiesOnly, map[string]string{"Authorization": "Bearer x"}, http.StatusForbidden},
		{"cookies only with transport header", httpx.CookiesOnly, map[string]string{"X-Egauth-Transport": "bearer"}, http.StatusForbidden},
		{"authorization bearer without transport header", httpx.CookiesAndBearer, map[string]string{"Authorization": "Bearer x"}, http.StatusForbidden},
		{"transport header selects bearer", httpx.CookiesAndBearer, map[string]string{"X-Egauth-Transport": "bearer"}, http.StatusOK},
		{"bearer only with authorization bearer", httpx.BearerOnly, map[string]string{"Authorization": "Bearer x"}, http.StatusOK},
		{"bearer only with transport header", httpx.BearerOnly, map[string]string{"X-Egauth-Transport": "bearer"}, http.StatusOK},
		{"bearer only with no credential header stays CSRF-checked", httpx.BearerOnly, nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.set.Transports = tc.allowed
			h := w.handler(t, loginMeta(), nil)
			r := post(`{}`, "application/json")
			r.Header.Set("Origin", "https://evil.example.org")
			r.Header.Del("Sec-Fetch-Site")
			for k, v := range tc.h {
				r.Header.Set(k, v)
			}
			if resp := serve(h, r); resp.Code != tc.status {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
		})
	}
}

func TestBearerCSRFExemptionOnAuthenticatedEndpointFollowsSessionTransport(t *testing.T) {
	for name, tc := range map[string]struct {
		transport core.Transport
		status    int
	}{
		"bearer session":  {core.TransportBearer, http.StatusOK},
		"cookies session": {core.TransportCookies, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.auth.attrs = attrs(core.ForTestAttrs{Subject: subject(acme), Factors: []core.Factor{core.FactorPassword}, PrimaryAt: start, Transport: tc.transport})
			meta := sensitiveMeta()
			meta.Sensitive, meta.SetsCookies = false, true
			h := w.handler(t, meta, nil)
			r := post(`{}`, "application/json")
			r.Header.Set("Origin", "https://evil.example.org")
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Set("Authorization", "Bearer x")
			resp := serve(h, r)
			if resp.Code != tc.status {
				t.Fatalf("status %d %s", resp.Code, resp.Body)
			}
			if tc.status != http.StatusOK && slices.Contains(w.rec.got(), "endpoint") {
				t.Fatal("endpoint ran after the refusal")
			}
		})
	}
}

func sessionActionMeta() httpx.Meta {
	return httpx.Meta{Authenticated: true, Mutation: true, BodyCap: httpx.FormBodyCap, SessionLimit: limiter.LoginClient}
}

func TestSessionLimitIsChargedOnTheLineageAfterAuthentication(t *testing.T) {
	w := newWorld(t)
	h := w.handler(t, sessionActionMeta(), nil)
	r := post(`{}`, "application/json")
	r.Header.Set("Cookie", "__Host-session=x")
	if resp := serve(h, r); resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body)
	}
	if want := []string{"tenant", "resume", "limit:login_client", "hook", "endpoint"}; !slices.Equal(w.rec.got(), want) {
		t.Fatalf("order %v want %v", w.rec.got(), want)
	}
	lineage := w.auth.attrs.Lineage().String()
	if len(w.lim.keys) != 1 || w.lim.keys[0].Value != "session:"+lineage || w.lim.keys[0].Value == "198.51.100.7" {
		t.Fatalf("session limit key %+v", w.lim.keys)
	}
}

func TestSessionLimitRefusalAndOptOut(t *testing.T) {
	w := newWorld(t)
	w.lim.deny[limiter.LoginClient] = true
	h := w.handler(t, sessionActionMeta(), nil)
	r := post(`{}`, "application/json")
	r.Header.Set("Cookie", "__Host-session=x")
	resp := serve(h, r)
	if resp.Code != http.StatusTooManyRequests || slices.Contains(w.rec.got(), "endpoint") {
		t.Fatalf("an exhausted session bucket must refuse: %d", resp.Code)
	}
	w2 := newWorld(t)
	w2.set.Insecure.NoRateLimit = true
	h2 := w2.handler(t, sessionActionMeta(), nil)
	r2 := post(`{}`, "application/json")
	r2.Header.Set("Cookie", "__Host-session=x")
	if resp := serve(h2, r2); resp.Code != http.StatusOK || len(w2.lim.keys) != 0 {
		t.Fatalf("NoRateLimit must skip the session limit: %d %v", resp.Code, w2.lim.keys)
	}
}
