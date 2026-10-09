package federationsvc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func (w *world) startLink(sess string) (*httptest.ResponseRecorder, *http.Cookie) {
	w.t.Helper()
	rec := w.do(call{method: http.MethodPost, target: origin + basePath + "/oauth/idp/link", session: sess, fields: map[string]string{}})
	return rec, bindCookie(rec)
}

func TestLinkAttachesTheIdentityToTheSessionSubjectOnly(t *testing.T) {
	w := newWorld(t)
	owner := w.user("alice@example.org")
	before, err := w.ids.CurrentEpoch(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	rec, bind := w.startLink(w.session(owner, core.TransportCookies))
	if rec.Code != http.StatusOK || bind == nil {
		t.Fatalf("link answered %d %s", rec.Code, rec.Body.String())
	}
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	got := w.callback(w.authorize(authURL), bind)
	if got.Code != http.StatusOK || decode(t, got)["state"] != "linked" {
		t.Fatalf("link callback answered %d %s", got.Code, got.Body.String())
	}
	if len(w.issuer.completions()) != 0 {
		t.Fatal("the link callback admitted a session")
	}
	l, err := w.linked("idp-sub-1")
	if err != nil || l.Subject != owner {
		t.Fatalf("link %+v, %v: want the session subject", l, err)
	}
	after, _ := w.ids.CurrentEpoch(context.Background(), owner)
	if after <= before {
		t.Fatal("linking did not bump the security epoch")
	}
	if !w.sink.has("credential.added") {
		t.Fatal("linking emitted no credential.added")
	}
	rec, _ = w.login(nil)
	done := w.issuer.completions()
	if rec.Code != http.StatusOK || len(done) != 1 || done[0].verified.Subject() != owner {
		t.Fatalf("sign-in through the linked identity: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLinkRequiresAFreshEstablishedSession(t *testing.T) {
	w := newWorld(t)
	rec := w.do(call{method: http.MethodPost, target: origin + basePath + "/oauth/idp/link", fields: map[string]string{}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous link answered %d %s", rec.Code, rec.Body.String())
	}
	m, ok := routes.MetaFor(routes.OAuthLink)
	if !ok || !m.Sensitive || !m.Authenticated {
		t.Fatalf("link metadata %+v: want Sensitive and Authenticated", m)
	}
	owner := w.user("alice@example.org")
	sess := w.session(owner, core.TransportCookies)
	w.clock.Advance(time.Hour)
	stale := w.do(call{method: http.MethodPost, target: origin + basePath + "/oauth/idp/link", session: sess, fields: map[string]string{}})
	if stale.Code != http.StatusForbidden || errorCode(t, stale) != "reauth_required" {
		t.Fatalf("a stale session linked: %d %s", stale.Code, stale.Body.String())
	}
}

func TestLinkIsRefusedFromABearerSession(t *testing.T) {
	w := newWorld(t)
	owner := w.user("alice@example.org")
	rec := w.do(call{method: http.MethodPost, target: origin + basePath + "/oauth/idp/link", bearer: true,
		session: w.session(owner, core.TransportBearer), fields: map[string]string{}})
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "unsupported_transport" {
		t.Fatalf("bearer link answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestLinkOfAnUnverifiedAccountIsRefused(t *testing.T) {
	w := newWorld(t)
	owner := w.user("alice@example.org")
	w.accounts.unverify(owner)
	rec := w.do(call{method: http.MethodPost, target: origin + basePath + "/oauth/idp/link", session: w.session(owner, core.TransportCookies), fields: map[string]string{}})
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "email_unverified" {
		t.Fatalf("link of an unverified account answered %d %s (§6.9.5)", rec.Code, rec.Body.String())
	}
}

func TestLinkOfAnIdentityOwnedElsewhereIsRefused(t *testing.T) {
	w := newWorld(t)
	if rec, _ := w.login(nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	other := w.user("bob@example.org")
	rec, bind := w.startLink(w.session(other, core.TransportCookies))
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	got := w.callback(w.authorize(authURL), bind)
	if got.Code != http.StatusConflict || errorCode(t, got) != "identity_already_linked" {
		t.Fatalf("stealing a linked identity answered %d %s", got.Code, got.Body.String())
	}
}

func TestLinkDiesWhenTheEpochMovesBeforeTheCallback(t *testing.T) {
	w := newWorld(t)
	owner := w.user("alice@example.org")
	rec, bind := w.startLink(w.session(owner, core.TransportCookies))
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	if _, err := w.ids.Apply(context.Background(), identity.BumpEpoch{Subject: owner, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	got := w.callback(w.authorize(authURL), bind)
	if got.Code != http.StatusUnauthorized {
		t.Fatalf("a link begun before a security change answered %d %s", got.Code, got.Body.String())
	}
	if _, err := w.linked("idp-sub-1"); err == nil {
		t.Fatal("a stale link ceremony attached the identity")
	}
}

func TestBearerLoginEndsInTheExchangeCeremony(t *testing.T) {
	w := newWorld(t)
	rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/idp/begin", bearer: true})
	body := decode(t, rec)
	authURL, _ := body["authorization_url"].(string)
	bind, _ := body["bind"].(string)
	if rec.Code != http.StatusOK || authURL == "" || bind == "" || bindCookie(rec) != nil {
		t.Fatalf("bearer begin answered %d %s", rec.Code, rec.Body.String())
	}
	cb := w.callback(w.authorize(authURL))
	cbBody := decode(t, cb)
	handle, _ := cbBody["handle"].(string)
	if cb.Code != http.StatusOK || cbBody["state"] != "exchange_required" || handle == "" {
		t.Fatalf("bearer callback answered %d %s", cb.Code, cb.Body.String())
	}
	if len(w.issuer.completions()) != 0 {
		t.Fatal("the browser leg of a bearer login was admitted before the exchange")
	}
	exchange := func(h, b string) *httptest.ResponseRecorder {
		return w.do(call{method: http.MethodPost, target: origin + basePath + "/exchange", bearer: true,
			fields: map[string]string{routes.FieldHandle: h, routes.FieldBind: b}})
	}
	if got := exchange(handle, strings.Repeat("A", len(bind))); got.Code != http.StatusBadRequest || errorCode(t, got) != "unbound_ceremony" {
		t.Fatalf("exchange without the bind answered %d %s", got.Code, got.Body.String())
	}
	enc, _, _ := strings.Cut(handle, ".")
	if got := exchange(enc+".other", bind); got.Code != http.StatusBadRequest || errorCode(t, got) != "invalid_token" {
		t.Fatalf("exchange with a relabelled provider answered %d %s", got.Code, got.Body.String())
	}
	got := exchange(handle, bind)
	if got.Code != http.StatusOK || decode(t, got)["state"] != "authenticated" {
		t.Fatalf("exchange answered %d %s", got.Code, got.Body.String())
	}
	done := w.issuer.completions()
	if len(done) != 1 || done[0].pending.Transport() != core.TransportBearer || done[0].verified.Provider() != "idp" {
		t.Fatalf("exchange completions %+v", done)
	}
	if again := exchange(handle, bind); again.Code != http.StatusBadRequest || errorCode(t, again) != "invalid_token" {
		t.Fatalf("a redeemed exchange answered %d %s", again.Code, again.Body.String())
	}
}

func TestBearerCallbackRedirectsToReturnToWithTheHandle(t *testing.T) {
	w := newWorld(t)
	rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/idp/begin", bearer: true,
		fields: map[string]string{routes.FieldReturnTo: "/app/done"}})
	authURL, _ := decode(t, rec)["authorization_url"].(string)
	cb := w.callback(w.authorize(authURL))
	if cb.Code != http.StatusSeeOther {
		t.Fatalf("bearer callback with return_to answered %d %s", cb.Code, cb.Body.String())
	}
	loc, err := url.Parse(cb.Header().Get("Location"))
	if err != nil || loc.Path != "/app/done" || loc.Query().Get(routes.FieldHandle) == "" || loc.Host != "" {
		t.Fatalf("bearer callback location %q", cb.Header().Get("Location"))
	}
}

func TestExchangeExpiresAfterSixtySeconds(t *testing.T) {
	w := newWorld(t)
	rec := w.do(call{method: http.MethodGet, target: origin + basePath + "/oauth/idp/begin", bearer: true})
	body := decode(t, rec)
	authURL, _ := body["authorization_url"].(string)
	bind, _ := body["bind"].(string)
	handle, _ := decode(t, w.callback(w.authorize(authURL)))["handle"].(string)
	w.clock.Advance(61e9)
	got := w.do(call{method: http.MethodPost, target: origin + basePath + "/exchange", bearer: true,
		fields: map[string]string{routes.FieldHandle: handle, routes.FieldBind: bind}})
	if got.Code != http.StatusBadRequest || errorCode(t, got) != "invalid_token" {
		t.Fatalf("a 61-second-old exchange answered %d %s", got.Code, got.Body.String())
	}
}
