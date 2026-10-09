package federationsvc_test

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	storefed "github.com/JLugagne/egauth/store/federation"
)

func (w *world) storeProvider(p federation.Provider) kek.KEK {
	w.t.Helper()
	sum := sha256.Sum256([]byte("egauth/federationsvc_test/kek"))
	k, err := kek.NewLocal(sum[:])
	if err != nil {
		w.t.Fatal(err)
	}
	ref, err := sealing.OAuthClientSecret(core.TenantID{}, p.Name)
	if err != nil {
		w.t.Fatal(err)
	}
	sealed, err := sealing.Seal(context.Background(), k, ref, []byte(p.ClientSecret.Reveal()))
	if err != nil {
		w.t.Fatal(err)
	}
	err = w.fed.PutProvider(context.Background(), storefed.ProviderSpec{
		Name: p.Name, ClientID: p.ClientID, SealedSecret: sealed, AADVersion: storefed.AADVersionCurrent,
		AuthURL: p.AuthURL, TokenURL: p.TokenURL, UserInfoURL: p.UserInfoURL, Scopes: p.Scopes,
		Issuer: p.Issuer, JWKSURL: p.JWKSURL, EmailVerification: federation.Always,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return k
}

func TestTenantProviderIsReadFromTheStoreAndCappedAtRuntime(t *testing.T) {
	w := newWorld(t, func(c *config) { c.perTenant = true })
	rec, _ := w.login(nil)
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "email_unverified" {
		t.Fatalf("a runtime provider without Domains adopted an email: %d %s", rec.Code, rec.Body.String())
	}
	w.user("existing@example.org")
	if rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/missing/begin"}); rec.Code != http.StatusNotFound {
		t.Fatalf("an unregistered tenant provider answered %d", rec.Code)
	}
}

func TestTenantProviderLogsInALinkedIdentity(t *testing.T) {
	w := newWorld(t, func(c *config) { c.perTenant = true })
	owner := w.user("alice@example.org")
	rec, bind := w.startLink(w.session(owner, core.TransportCookies))
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	if got := w.callback(w.authorize(authURL), bind); got.Code != http.StatusOK {
		t.Fatalf("link through a tenant provider answered %d %s", got.Code, got.Body.String())
	}
	got, _ := w.login(nil)
	if got.Code != http.StatusOK || w.issuer.completions()[0].verified.Subject() != owner {
		t.Fatalf("tenant provider sign-in answered %d %s", got.Code, got.Body.String())
	}
}
