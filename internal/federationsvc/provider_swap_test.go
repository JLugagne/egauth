package federationsvc_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
)

func trustingClient(idps ...*fakeIdP) *http.Client {
	pool := x509.NewCertPool()
	for _, p := range idps {
		pool.AddCert(p.server.Certificate())
	}
	return &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type blockPath struct {
	inner http.RoundTripper
	path  string
}

func (b blockPath) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == b.path {
		return nil, errors.New("blocked by the tenant dial guard")
	}
	return b.inner.RoundTrip(r)
}

func (w *world) loginVia(provider string) *http.Response {
	w.t.Helper()
	rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/" + provider + "/begin"})
	if rec.Code != http.StatusSeeOther {
		w.t.Fatalf("begin answered %d %s", rec.Code, rec.Body.String())
	}
	return w.callback(w.authorize(rec.Header().Get("Location")), bindCookie(rec)).Result()
}

func TestReplacedTenantProviderCannotSignInAsALinkedUser(t *testing.T) {
	w := newWorld(t, func(c *config) { c.perTenant, c.attacker = true, true })
	owner := w.user("alice@example.org")
	rec, bind := w.startLink(w.session(owner, core.TransportCookies))
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	if got := w.callback(w.authorize(authURL), bind); got.Code != http.StatusOK {
		t.Fatalf("link through the tenant provider answered %d %s", got.Code, got.Body.String())
	}
	w.storeProvider(w.attacker.provider("idp", federation.Always))
	w.attacker.setUser(idpUser{Subject: "idp-sub-1", Email: "mallory@evil.example", EmailVerified: true})

	got, _ := w.login(nil)
	for _, c := range w.issuer.completions() {
		if c.verified.Subject() == owner {
			t.Fatalf("a provider replaced under the same name signed in as the linked user: %d %s", got.Code, got.Body.String())
		}
	}
	if got.Code == http.StatusOK {
		t.Fatalf("the replaced provider admitted a session: %s", got.Body.String())
	}
}

func TestTenantJWKSIsNeverServedFromTheStaticCache(t *testing.T) {
	w := newWorld(t, func(c *config) { c.tenantToo, c.tenantBlocks = true, "/jwks" })
	w.user("alice@example.org")
	if rec, _ := w.login(nil); rec.Code == http.StatusInternalServerError {
		t.Fatalf("static sign-in answered %d %s", rec.Code, rec.Body.String())
	}
	got := w.loginVia("corp")
	if got.StatusCode != http.StatusBadGateway {
		t.Fatalf("a tenant provider reused the JWKS the static scope fetched: answered %d", got.StatusCode)
	}
}
