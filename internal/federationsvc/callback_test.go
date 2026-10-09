package federationsvc_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/federationsvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func TestNewAccountEndsInCompleteWithTheFedFactor(t *testing.T) {
	w := newWorld(t)
	rec, _ := w.login(nil)
	if rec.Code != http.StatusOK || decode(t, rec)["state"] != "authenticated" {
		t.Fatalf("callback answered %d %s", rec.Code, rec.Body.String())
	}
	done := w.issuer.completions()
	if len(done) != 1 {
		t.Fatalf("Complete called %d times, want once (O-01)", len(done))
	}
	v := done[0].verified
	if fs := v.Factors(); len(fs) != 1 || fs[0] != core.FactorFederated || v.Provider() != "idp" {
		t.Fatalf("Complete got factors %v provider %q, want fed from idp", fs, v.Provider())
	}
	l, err := w.linked("idp-sub-1")
	if err != nil {
		t.Fatalf("the new account is not linked: %v", err)
	}
	if l.Subject != v.Subject() || l.ProviderEmail != "alice@example.org" || !l.ProviderEmailVerified {
		t.Fatalf("link %+v does not record the verified provider email for %v", l, v.Subject())
	}
	u, err := w.ids.GetUser(context.Background(), v.Subject())
	if err != nil || u.Email.Value() != "alice@example.org" || u.EmailVerifiedAt.IsZero() {
		t.Fatalf("new account %+v, %v: want the verified provider email", u, err)
	}
	if !w.sink.has("user.registered") {
		t.Fatal("a federated sign-up emits no user.registered")
	}
}

func TestEnrolledUserGetsTheMFAStepThroughComplete(t *testing.T) {
	w := newWorld(t)
	rec, _ := w.login(nil)
	sub := w.issuer.completions()[0].verified.Subject()
	w.issuer.mfa[sub] = true
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	rec, _ = w.login(nil)
	if decode(t, rec)["state"] != "mfa_required" {
		t.Fatalf("an enrolled user signing in through the provider skipped MFA (O-01): %s", rec.Body.String())
	}
}

func TestLinkedIdentityLogsIntoItsAccount(t *testing.T) {
	w := newWorld(t)
	first, _ := w.login(nil)
	if first.Code != http.StatusOK {
		t.Fatal(first.Body.String())
	}
	w.idp.setUser(idpUser{Subject: "idp-sub-1", Email: "renamed@example.org", EmailVerified: true})
	rec, _ := w.login(nil)
	done := w.issuer.completions()
	if rec.Code != http.StatusOK || len(done) != 2 || done[0].verified.Subject() != done[1].verified.Subject() {
		t.Fatalf("the linked identity did not log into its account: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExistingEmailIsNeverAutoLinked(t *testing.T) {
	w := newWorld(t)
	owner := w.user("alice@example.org")
	rec, _ := w.login(nil)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "account_exists" {
		t.Fatalf("existing email answered %d %s, want 409 account_exists (D6)", rec.Code, rec.Body.String())
	}
	if len(w.issuer.completions()) != 0 {
		t.Fatal("an existing account was admitted through an unlinked provider identity")
	}
	if _, err := w.linked("idp-sub-1"); err == nil {
		t.Fatal("the provider identity was attached to the existing account")
	}
	links, err := w.fed.LinkedFor(context.Background(), owner)
	if err != nil || len(links) != 0 {
		t.Fatalf("owner links %v, %v: want none", links, err)
	}
}

func TestAccountExistsIsUniformWithAnUnknownSubjectCase(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.org")
	a, _ := w.login(nil)
	w.idp.setUser(idpUser{Subject: "idp-sub-2", Email: "alice@example.org", EmailVerified: true})
	b, _ := w.login(nil)
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("account_exists differs between identities: %s vs %s", a.Body.String(), b.Body.String())
	}
}

func TestUnverifiedProviderEmailCreatesNothing(t *testing.T) {
	w := newWorld(t)
	w.idp.setUser(idpUser{Subject: "idp-sub-1", Email: "bob@example.org", EmailVerified: false})
	rec, _ := w.login(nil)
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "email_unverified" {
		t.Fatalf("unverified email answered %d %s, want 403 email_unverified (O-04)", rec.Code, rec.Body.String())
	}
	if _, err := w.ids.FindUser(context.Background(), core.TenantID{}, mustEmail(t, "bob@example.org")); err == nil {
		t.Fatal("an account was created with an unverified provider email")
	}
}

func TestNeverProviderEmailIsNotTrustedEvenWhenClaimed(t *testing.T) {
	w := newWorld(t, func(c *config) { c.ev = federation.Never })
	rec, _ := w.login(nil)
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "email_unverified" {
		t.Fatalf("a Never provider's claimed email answered %d %s (O-04)", rec.Code, rec.Body.String())
	}
}

func TestUnverifiedEmailNeverRevealsAnExistingAccount(t *testing.T) {
	w := newWorld(t)
	w.user("carol@example.org")
	w.idp.setUser(idpUser{Subject: "idp-sub-1", Email: "carol@example.org", EmailVerified: false})
	a, _ := w.login(nil)
	w.idp.setUser(idpUser{Subject: "idp-sub-2", Email: "nobody@example.org", EmailVerified: false})
	b, _ := w.login(nil)
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("an unverified email told existing from unknown: %s vs %s", a.Body.String(), b.Body.String())
	}
}

func TestInviteOnlyCreatesNoAccount(t *testing.T) {
	w := newWorld(t, func(c *config) { c.registration = federationsvc.RegistrationInviteOnly })
	rec, _ := w.login(nil)
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "registration_closed" {
		t.Fatalf("invite-only answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestRememberAndReturnToAreSealedAtBegin(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(map[string]string{routes.FieldRemember: "true", routes.FieldReturnTo: "/billing?tab=2"})
	bind := bindCookie(rec)
	cb := w.authorize(rec.Header().Get("Location"))
	u, err := url.Parse(cb)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set(routes.FieldRemember, "false")
	q.Set(routes.FieldReturnTo, "/elsewhere")
	u.RawQuery = q.Encode()
	if got := w.callback(u.String(), bind); got.Code != http.StatusOK {
		t.Fatal(got.Body.String())
	}
	p := w.issuer.completions()[0].pending
	if !p.RememberMe() || p.ReturnTo() != "/billing?tab=2" || p.Transport() != core.TransportCookies {
		t.Fatalf("callback replayed remember=%v return_to=%q transport=%v, want the begin values (O-02)", p.RememberMe(), p.ReturnTo(), p.Transport())
	}
}

func TestRedirectURIIsDerivedFromOriginAndBasePath(t *testing.T) {
	w := newWorld(t)
	if rec, _ := w.login(nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	want := origin + basePath + "/oauth/idp/callback"
	if got := w.idp.last().RedirectURI; got != want {
		t.Fatalf("authorization redirect_uri %q, want %q (O-08)", got, want)
	}
	red := w.idp.redemptions()
	if len(red) != 1 || red[0].Get("redirect_uri") != want {
		t.Fatalf("token exchange redirect_uri %v, want the sealed %q", red, want)
	}
	if red[0].Get("code_verifier") == "" || w.idp.last().Challenge == "" {
		t.Fatal("PKCE was not used")
	}
}

func TestCallbackWithoutBindCookieIsUnboundAndKeepsTheState(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb := w.authorize(rec.Header().Get("Location"))
	got := w.callback(cb)
	if got.Code != http.StatusBadRequest || errorCode(t, got) != "unbound_ceremony" {
		t.Fatalf("callback without bind answered %d %s, want 400 unbound_ceremony", got.Code, got.Body.String())
	}
	wrong := *bind
	wrong.Value = strings.Repeat("A", len(bind.Value))
	if got := w.callback(cb, &wrong); got.Code != http.StatusBadRequest || errorCode(t, got) != "unbound_ceremony" {
		t.Fatalf("callback with a foreign bind answered %d %s", got.Code, got.Body.String())
	}
	if got := w.callback(cb, bind); got.Code != http.StatusOK {
		t.Fatalf("an unbound attempt consumed the victim's state: %d %s", got.Code, got.Body.String())
	}
}

func TestCallbackStateIsSingleUse(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb := w.authorize(rec.Header().Get("Location"))
	if got := w.callback(cb, bind); got.Code != http.StatusOK {
		t.Fatal(got.Body.String())
	}
	if got := w.callback(cb, bind); got.Code != http.StatusBadRequest || errorCode(t, got) != "invalid_state" {
		t.Fatalf("replayed state answered %d %s", got.Code, got.Body.String())
	}
}

func TestExpiredStateIsRefused(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb := w.authorize(rec.Header().Get("Location"))
	w.clock.Advance(time.Hour)
	if got := w.callback(cb, bind); got.Code != http.StatusBadRequest || errorCode(t, got) != "invalid_state" {
		t.Fatalf("expired state answered %d %s (O-07)", got.Code, got.Body.String())
	}
}

func TestStateOfAnotherProviderPathIsRefused(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb := strings.Replace(w.authorize(rec.Header().Get("Location")), "/oauth/idp/", "/oauth/other/", 1)
	if got := w.callback(cb, bind); got.Code != http.StatusBadRequest || errorCode(t, got) != "invalid_state" {
		t.Fatalf("state replayed on another provider path answered %d %s", got.Code, got.Body.String())
	}
}

func TestStateOfAnotherTenantIsRefusedUnconsumed(t *testing.T) {
	w := newWorld(t, func(c *config) { c.tenants = headerTenants{}; c.tenant = "acme" })
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb := w.authorize(rec.Header().Get("Location"))
	if got := w.do(call{method: http.MethodGet, target: cb, cookies: []*http.Cookie{bind}, tenant: "globex"}); got.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant state answered %d %s, want 401", got.Code, got.Body.String())
	}
	if got := w.callback(cb, bind); got.Code != http.StatusOK {
		t.Fatalf("the cross-tenant attempt consumed the state: %d %s", got.Code, got.Body.String())
	}
}

func TestIssuerParameterMustBeTheSpecIssuer(t *testing.T) {
	w := newWorld(t)
	w.idp.setTamper(tokenTamper{IssParam: "https://evil.example.com"})
	rec, _ := w.login(nil)
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "issuer_mismatch" {
		t.Fatalf("foreign iss answered %d %s (RFC 9207)", rec.Code, rec.Body.String())
	}
	if len(w.idp.redemptions()) != 0 {
		t.Fatal("the code was redeemed despite the issuer mismatch")
	}
}

func TestPathScopedIssuerIsAccepted(t *testing.T) {
	w := newWorld(t, func(c *config) { c.issuerPath = "/realms/acme" })
	if rec, _ := w.login(nil); rec.Code != http.StatusOK {
		t.Fatalf("a path-scoped issuer was refused (O-03): %d %s", rec.Code, rec.Body.String())
	}
}

func TestIDTokenIsVerified(t *testing.T) {
	cases := map[string]tokenTamper{
		"wrong audience":   {Audience: "someone-else"},
		"wrong issuer":     {Issuer: "https://evil.example.com"},
		"wrong nonce":      {Nonce: "not-the-nonce"},
		"expired":          {ExpiresIn: -time.Hour},
		"foreign key":      {ForeignKey: true},
		"no id token":      {OmitIDToken: true},
		"symmetric alg":    {Alg: "HS256"},
		"unsigned":         {Alg: "none"},
		"userinfo differs": {UserInfoSubID: "someone-else"},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			if name == "userinfo differs" {
				w.idp.setUser(idpUser{Subject: "idp-sub-1"})
			}
			w.idp.setTamper(tamper)
			rec, _ := w.login(nil)
			if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != "invalid_identity" || len(w.issuer.completions()) != 0 {
				t.Fatalf("a tampered id_token answered %d %s, want 401 invalid_identity", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIDTokenAlgorithmsOfTheJWKSAreAccepted(t *testing.T) {
	for _, alg := range []string{"ES256", "RS256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			w := newWorld(t)
			w.idp.setTamper(tokenTamper{Alg: alg})
			if rec, _ := w.login(nil); rec.Code != http.StatusOK {
				t.Fatalf("%s id_token refused: %d %s", alg, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPlainOAuthProviderUsesUserInfo(t *testing.T) {
	w := newWorld(t, func(c *config) { c.oidc = false })
	rec, _ := w.login(nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("plain OAuth sign-in answered %d %s", rec.Code, rec.Body.String())
	}
	if _, err := w.linked("4242"); err != nil {
		t.Fatalf("plain OAuth identity not linked by its numeric id: %v", err)
	}
}

func TestProviderErrorConsumesTheStateAndAdmitsNothing(t *testing.T) {
	w := newWorld(t)
	rec := w.begin(nil)
	bind := bindCookie(rec)
	cb, err := url.Parse(w.authorize(rec.Header().Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	q := cb.Query()
	q.Set("error", "access_denied")
	cb.RawQuery = q.Encode()
	if got := w.callback(cb.String(), bind); got.Code != http.StatusBadRequest || errorCode(t, got) != "access_denied" {
		t.Fatalf("provider error answered %d %s", got.Code, got.Body.String())
	}
	if len(w.idp.redemptions()) != 0 || len(w.issuer.completions()) != 0 {
		t.Fatal("a provider error still redeemed or admitted")
	}
}

func TestUnknownProviderIs404(t *testing.T) {
	w := newWorld(t)
	rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/nope/begin"})
	if rec.Code != http.StatusNotFound || errorCode(t, rec) != "unknown_provider" {
		t.Fatalf("unknown provider answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestDiscoveryPinsTheIssuer(t *testing.T) {
	w := newWorld(t, func(c *config) { c.discover = true })
	if rec, _ := w.login(nil); rec.Code != http.StatusOK {
		t.Fatalf("a discovered provider failed: %d %s", rec.Code, rec.Body.String())
	}
	spec := w.idp.provider("idp", federation.Always)
	spec.AuthURL, spec.TokenURL, spec.UserInfoURL, spec.JWKSURL = "", "", "", ""
	w.idp.setTamper(tokenTamper{Issuer: "https://other.example.com"})
	if _, err := federationsvc.DiscoverWithHTTPClient(context.Background(), w.idp.client(), spec); err == nil {
		t.Fatal("a discovery document naming another issuer was accepted")
	}
}

func TestOneCallbackPathOnly(t *testing.T) {
	w := newWorld(t)
	eps, err := w.svc.Endpoints(w.issuer)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	callbacks := 0
	for _, e := range eps {
		paths = append(paths, e.Path)
		if strings.Contains(e.Path, "callback") {
			callbacks++
		}
	}
	if callbacks != 1 {
		t.Fatalf("endpoints %v expose %d callback paths, want exactly one (O-06)", paths, callbacks)
	}
	want := map[string]bool{routes.OAuthBegin: true, routes.OAuthCallback: true, routes.OAuthLink: true, routes.Exchange: true}
	if len(paths) != len(want) {
		t.Fatalf("endpoints %v", paths)
	}
	for _, p := range paths {
		if !want[p] {
			t.Fatalf("unexpected endpoint %s", p)
		}
	}
	if _, err := w.svc.Endpoints(nil); err == nil {
		t.Fatal("Endpoints accepted a nil issuer")
	}
}

func mustEmail(t *testing.T, raw string) identity.Identifier {
	t.Helper()
	id, err := identity.NewIdentifier(identity.IdentifierEmail, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
