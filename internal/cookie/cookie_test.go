package cookie_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/store/ceremony"
)

func policy(t *testing.T, o cookie.Options) cookie.Policy {
	t.Helper()
	p, err := cookie.NewPolicy(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func written(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("want one cookie, got %d", len(cs))
	}
	return cs[0]
}

func rawHeader(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	h := w.Result().Header.Values("Set-Cookie")
	if len(h) != 1 {
		t.Fatalf("want one Set-Cookie, got %d", len(h))
	}
	return h[0]
}

func TestClassesAreClosed(t *testing.T) {
	want := map[cookie.Name]cookie.Class{
		cookie.AccessToken:     cookie.ClassSession,
		cookie.RefreshToken:    cookie.ClassSession,
		cookie.StatefulSession: cookie.ClassSession,
		cookie.Flow:            cookie.ClassFlow,
		cookie.Bind:            cookie.ClassBind,
	}
	if len(cookie.Names()) != len(want) {
		t.Fatalf("names %v", cookie.Names())
	}
	for _, n := range cookie.Names() {
		if n.Class() != want[n] {
			t.Errorf("%v: class %v want %v", n, n.Class(), want[n])
		}
	}
	if cookie.Name(0).Class() != 0 || cookie.Name(99).Class() != 0 {
		t.Fatal("undeclared names have no class")
	}
}

func TestNamesPerPolicy(t *testing.T) {
	host := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	shared := policy(t, cookie.Options{PublicOrigin: "https://app.example.com", SharedDomain: "example.com"})
	loop := policy(t, cookie.Options{PublicOrigin: "http://localhost:8080"})
	cases := []struct {
		n                      cookie.Name
		host, shared, loopback string
	}{
		{cookie.AccessToken, "__Host-access_token", "__Secure-access_token", "access_token"},
		{cookie.RefreshToken, "__Host-refresh_token", "__Secure-refresh_token", "refresh_token"},
		{cookie.StatefulSession, "__Host-session", "__Secure-session", "session"},
		{cookie.Flow, "__Host-egauth_flow", "__Host-egauth_flow", "egauth_flow"},
		{cookie.Bind, "__Host-egauth_bind", "__Host-egauth_bind", "egauth_bind"},
	}
	for _, tc := range cases {
		if got := host.CookieName(tc.n); got != tc.host {
			t.Errorf("host %v: %q", tc.n, got)
		}
		if got := shared.CookieName(tc.n); got != tc.shared {
			t.Errorf("shared %v: %q", tc.n, got)
		}
		if got := loop.CookieName(tc.n); got != tc.loopback {
			t.Errorf("loopback %v: %q", tc.n, got)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []cookie.Options{
		{},
		{PublicOrigin: "http://app.example.com"},
		{PublicOrigin: "https://app.example.com/path"},
		{PublicOrigin: "https://app.example.com", SharedDomain: "other.com"},
		{PublicOrigin: "https://app.example.com", SharedDomain: "ample.com"},
		{PublicOrigin: "https://app.example.com", SharedDomain: ".example.com"},
		{PublicOrigin: "http://localhost:8080", SharedDomain: "localhost"},
	}
	for _, o := range bad {
		if _, err := cookie.NewPolicy(o); !errors.Is(err, cookie.ErrInvalidPolicy) {
			t.Errorf("%+v: want ErrInvalidPolicy, got %v", o, err)
		}
	}
	good := []cookie.Options{
		{PublicOrigin: "https://{tenant}.example.com"},
		{PublicOrigin: "https://app.example.com", SharedDomain: "EXAMPLE.com"},
		{PublicOrigin: "http://127.0.0.1:9000"},
		{PublicOrigin: "http://[::1]:9000"},
		{PublicOrigin: "https://localhost"},
	}
	for _, o := range good {
		if _, err := cookie.NewPolicy(o); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
}

func TestSessionClassAttributes(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	for _, n := range []cookie.Name{cookie.AccessToken, cookie.RefreshToken, cookie.StatefulSession} {
		t.Run(p.CookieName(n), func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := p.SetSession(w, n, "v.al-ue_1", false, time.Hour); err != nil {
				t.Fatal(err)
			}
			c := written(t, w)
			raw := rawHeader(t, w)
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
				t.Fatalf("attributes %+v", c)
			}
			if strings.Contains(raw, "Max-Age") || strings.Contains(raw, "Expires") {
				t.Fatalf("non-remembered session cookie must be a browser-session cookie: %s", raw)
			}
			w = httptest.NewRecorder()
			if err := p.SetSession(w, n, "v", true, 90*time.Minute+500*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if c := written(t, w); c.MaxAge != 5400 {
				t.Fatalf("remembered Max-Age %d", c.MaxAge)
			}
		})
	}
}

func TestSessionRememberNeedsPositiveLifetime(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	for _, d := range []time.Duration{0, -time.Second, 500 * time.Millisecond} {
		if err := p.SetSession(httptest.NewRecorder(), cookie.AccessToken, "v", true, d); !errors.Is(err, cookie.ErrInvalidCookie) {
			t.Errorf("%v: want ErrInvalidCookie, got %v", d, err)
		}
	}
}

func TestSharedDomainDemotesOnlySessionClass(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com", SharedDomain: "example.com"})
	w := httptest.NewRecorder()
	if err := p.SetSession(w, cookie.RefreshToken, "v", false, 0); err != nil {
		t.Fatal(err)
	}
	if c := written(t, w); c.Name != "__Secure-refresh_token" || c.Domain != "example.com" || !c.Secure {
		t.Fatalf("shared session cookie %+v", c)
	}
	w = httptest.NewRecorder()
	if err := p.SetFlow(w, "v", ceremony.MFAFlow); err != nil {
		t.Fatal(err)
	}
	if c := written(t, w); c.Name != "__Host-egauth_flow" || c.Domain != "" {
		t.Fatalf("flow cookie must stay host-only %+v", c)
	}
	w = httptest.NewRecorder()
	b, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetBind(w, b, ceremony.OAuthState); err != nil {
		t.Fatal(err)
	}
	if c := written(t, w); c.Name != "__Host-egauth_bind" || c.Domain != "" {
		t.Fatalf("bind cookie must stay host-only %+v", c)
	}
}

func TestFlowClassAttributes(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	w := httptest.NewRecorder()
	if err := p.SetFlow(w, "handle", ceremony.MFAFlow); err != nil {
		t.Fatal(err)
	}
	c := written(t, w)
	if c.Name != "__Host-egauth_flow" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("flow attributes %+v", c)
	}
	if c.MaxAge != int(ceremony.MFAFlow.TTL()/time.Second) {
		t.Fatalf("flow Max-Age %d", c.MaxAge)
	}
	if err := p.SetFlow(httptest.NewRecorder(), "v", ceremony.Kind(0)); !errors.Is(err, cookie.ErrInvalidCookie) {
		t.Fatalf("zero kind: %v", err)
	}
}

func TestBindClassAttributes(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	b, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := p.SetBind(w, b, ceremony.OAuthState); err != nil {
		t.Fatal(err)
	}
	c := written(t, w)
	if c.Name != "__Host-egauth_bind" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("bind attributes %+v", c)
	}
	if c.MaxAge != int(ceremony.OAuthState.TTL()/time.Second) || c.Value != b.Value() {
		t.Fatalf("bind Max-Age %d value %q", c.MaxAge, c.Value)
	}
	if err := p.SetBind(httptest.NewRecorder(), cookie.BindSecret{}, ceremony.OAuthState); !errors.Is(err, cookie.ErrInvalidCookie) {
		t.Fatalf("zero bind: %v", err)
	}
}

func TestLoopbackIsNotSecure(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "http://localhost:8080"})
	w := httptest.NewRecorder()
	if err := p.SetSession(w, cookie.AccessToken, "v", false, 0); err != nil {
		t.Fatal(err)
	}
	if c := written(t, w); c.Secure || c.Name != "access_token" || !c.HttpOnly {
		t.Fatalf("loopback cookie %+v", c)
	}
	https := policy(t, cookie.Options{PublicOrigin: "https://localhost"})
	w = httptest.NewRecorder()
	if err := https.SetSession(w, cookie.AccessToken, "v", false, 0); err != nil {
		t.Fatal(err)
	}
	if c := written(t, w); !c.Secure || c.Name != "__Host-access_token" {
		t.Fatalf("https loopback cookie %+v", c)
	}
}

func TestWritersRejectWrongClass(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	if err := p.SetSession(httptest.NewRecorder(), cookie.Flow, "v", false, 0); !errors.Is(err, cookie.ErrInvalidCookie) {
		t.Fatalf("flow through SetSession: %v", err)
	}
	if err := p.SetSession(httptest.NewRecorder(), cookie.Bind, "v", false, 0); !errors.Is(err, cookie.ErrInvalidCookie) {
		t.Fatalf("bind through SetSession: %v", err)
	}
}

func TestValuesAreValidated(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	for _, v := range []string{"", "a b", "a;b", "a\"b", "a,b", "a\\b", strings.Repeat("a", 4097), "é"} {
		if err := p.SetSession(httptest.NewRecorder(), cookie.AccessToken, v, false, 0); !errors.Is(err, cookie.ErrInvalidCookie) {
			t.Errorf("%q: want ErrInvalidCookie, got %v", v, err)
		}
	}
}

func TestClearMatchesWriterAttributes(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com", SharedDomain: "example.com"})
	for _, n := range cookie.Names() {
		w := httptest.NewRecorder()
		p.Clear(w, n)
		c := written(t, w)
		if c.Name != p.CookieName(n) || c.MaxAge != -1 || c.Value != "" || c.Path != "/" || !c.Secure {
			t.Fatalf("clear %v: %+v", n, c)
		}
		if n.Class() == cookie.ClassSession && c.Domain != "example.com" {
			t.Fatalf("clear of a shared session cookie must carry the domain: %+v", c)
		}
	}
}

func TestReadRoundTripAndAmbiguity(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	w := httptest.NewRecorder()
	if err := p.SetSession(w, cookie.AccessToken, "tok", false, 0); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	if v, ok := p.Read(r, cookie.AccessToken); !ok || v != "tok" {
		t.Fatalf("read %q %v", v, ok)
	}
	if _, ok := p.Read(r, cookie.RefreshToken); ok {
		t.Fatal("absent cookie read as present")
	}
	r.AddCookie(&http.Cookie{Name: "__Host-access_token", Value: "tossed"})
	if _, ok := p.Read(r, cookie.AccessToken); ok {
		t.Fatal("two cookies with one name must read as absent")
	}
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.AddCookie(&http.Cookie{Name: "access_token", Value: "unprefixed"})
	if _, ok := p.Read(plain, cookie.AccessToken); ok {
		t.Fatal("an unprefixed cookie must not satisfy a prefixed name")
	}
}

func TestPresent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if cookie.Present(r) {
		t.Fatal("no cookie header")
	}
	r.Header.Set("Cookie", "garbage-without-equals")
	if !cookie.Present(r) {
		t.Fatal("any Cookie header counts, even unparsable")
	}
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "analytics", Value: "1"})
	if !cookie.Present(r) {
		t.Fatal("third-party cookie counts")
	}
}

func TestBindSecretAndConstantTimeVerify(t *testing.T) {
	a, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	b, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	if a.Value() == b.Value() || len(a.Value()) != 43 {
		t.Fatalf("bind values %q %q", a.Value(), b.Value())
	}
	sum := sha256.Sum256([]byte(a.Value()))
	if string(a.Hash()) != string(sum[:]) {
		t.Fatal("hash is SHA-256 of the value")
	}
	if !cookie.VerifyBind(a.Value(), a.Hash()) {
		t.Fatal("matching bind refused")
	}
	for _, tc := range []struct {
		presented string
		sealed    []byte
	}{
		{b.Value(), a.Hash()},
		{"", a.Hash()},
		{a.Value(), nil},
		{a.Value(), a.Hash()[:31]},
		{"", nil},
	} {
		if cookie.VerifyBind(tc.presented, tc.sealed) {
			t.Errorf("accepted %q against %x", tc.presented, tc.sealed)
		}
	}
}

func TestBindSecretIsRedacted(t *testing.T) {
	b, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(b), fmt.Sprintf("%#v", b), fmt.Sprintf("%+v", b), b.LogValue().String()} {
		if strings.Contains(s, b.Value()) {
			t.Fatalf("bind value leaked: %s", s)
		}
	}
}

func TestReadBind(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://app.example.com"})
	b, err := cookie.NewBind()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := p.SetBind(w, b, ceremony.MagicLink); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	v, ok := p.Read(r, cookie.Bind)
	if !ok || !cookie.VerifyBind(v, b.Hash()) {
		t.Fatal("bind cookie does not verify after a round trip")
	}
}

func TestSharedDomainRefusedForTenantSubdomainOrigin(t *testing.T) {
	for _, d := range []string{"example.com", "tenant.example.com"} {
		if _, err := cookie.NewPolicy(cookie.Options{PublicOrigin: "https://{tenant}.example.com", SharedDomain: d}); !errors.Is(err, cookie.ErrInvalidPolicy) {
			t.Fatalf("%s: tenant hosts must keep host-only session cookies, got %v", d, err)
		}
	}
	if _, err := cookie.NewPolicy(cookie.Options{PublicOrigin: "https://{tenant}.example.com"}); err != nil {
		t.Fatalf("host-only tenant policy: %v", err)
	}
}

func TestDiscardDropsQueuedCookies(t *testing.T) {
	p := policy(t, cookie.Options{PublicOrigin: "https://acme.example.com"})
	w := httptest.NewRecorder()
	if err := p.SetSession(w, cookie.AccessToken, "v", false, time.Minute); err != nil {
		t.Fatal(err)
	}
	w.Header().Set("X-Other", "kept")
	cookie.Discard(w)
	if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-Other") != "kept" {
		t.Fatalf("headers %v", w.Header())
	}
}
