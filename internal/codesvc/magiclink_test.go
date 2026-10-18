package codesvc_test

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func (w *world) requestLink(email string, fields map[string]string) (*http.Cookie, string) {
	w.t.Helper()
	f := map[string]string{routes.FieldIdentifier: email}
	maps.Copy(f, fields)
	before := len(w.mail.all())
	rec := w.do(req{path: routes.MagicLinkRequest, fields: f})
	if rec.Code != http.StatusAccepted {
		w.t.Fatalf("request = %d %s", rec.Code, rec.Body.String())
	}
	msgs := w.waitSent(w.mail, before+1)
	return bindCookie(rec), tokenOf(w.t, msgs[len(msgs)-1].link)
}

func TestMagicLinkRequestIsUniform(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	disabled := w.user("dis@example.com")
	if _, err := w.raw.Apply(context.Background(), identity.SetDisabledState{Subject: disabled, Disable: true}); err != nil {
		t.Fatal(err)
	}
	unverified := w.user("unv@example.com")
	w.accounts.unverified[unverified] = true
	var bodies []string
	for _, email := range []string{"ann@example.com", "nobody@example.com", "dis@example.com", "unv@example.com", "not-an-email"} {
		rec := w.do(req{path: routes.MagicLinkRequest, fields: map[string]string{routes.FieldIdentifier: email}})
		if rec.Code != http.StatusAccepted || bindCookie(rec) == nil {
			t.Fatalf("%s: %d %s", email, rec.Code, rec.Body.String())
		}
		bodies = append(bodies, rec.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("bodies differ: %q vs %q", b, bodies[0])
		}
	}
	w.flush()
	msgs := w.mail.all()
	if len(msgs) != 1 || msgs[0].to != "ann@example.com" || msgs[0].kind != "magic_link" {
		t.Fatalf("messages = %+v; only the usable verified account gets a link (§6.9)", msgs)
	}
}

func TestMagicLinkReplaysRememberAndReturnToFromTheRequest(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	bind, token := w.requestLink("ann@example.com", map[string]string{routes.FieldRemember: "true", routes.FieldReturnTo: "/dashboard?tab=1"})
	rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{bind}, fields: map[string]string{
		routes.FieldToken: token, routes.FieldRemember: "false", routes.FieldReturnTo: "/elsewhere",
	}})
	if rec.Code != http.StatusOK || decode(t, rec)["state"] != "authenticated" {
		t.Fatalf("consume = %d %s", rec.Code, rec.Body.String())
	}
	cs := w.issuer.completions()
	if len(cs) != 1 {
		t.Fatalf("completions = %d", len(cs))
	}
	p := cs[0].pending
	if !p.RememberMe() || p.ReturnTo() != "/dashboard?tab=1" {
		t.Fatalf("pending remember=%v returnTo=%q; want the request-time choice (I-14)", p.RememberMe(), p.ReturnTo())
	}
	if s, bound := p.Subject(); !bound || s != sub {
		t.Fatalf("pending subject = %v %v", s, bound)
	}
}

func TestMagicLinkEndsInCompleteWithTheEmailLinkFactor(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	w.issuer.mfa[sub] = true
	bind, token := w.requestLink("ann@example.com", nil)
	rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{bind}, fields: map[string]string{routes.FieldToken: token}})
	if rec.Code != http.StatusOK || decode(t, rec)["state"] != "mfa_required" {
		t.Fatalf("consume for an enrolled user = %d %s; want mfa_required (I-04)", rec.Code, rec.Body.String())
	}
	cs := w.issuer.completions()
	if len(cs) != 1 || !slices.Equal(cs[0].verified.Factors(), []core.Factor{core.FactorEmailLink}) || cs[0].verified.Subject() != sub {
		t.Fatalf("completion = %+v", cs)
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > 0 {
			t.Fatalf("the service set a credential itself: %s", c.Name)
		}
	}
}

func TestMagicLinkFromAnotherBrowserNeedsConfirmation(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	_, token := w.requestLink("ann@example.com", nil)
	rec := w.do(req{path: routes.MagicLink, fields: map[string]string{routes.FieldToken: token}})
	body := decode(t, rec)
	if rec.Code != http.StatusOK || body["state"] != "confirm_required" || body["account_hint"] != "a***@example.com" {
		t.Fatalf("unbound consume = %d %v", rec.Code, body)
	}
	if len(w.issuer.completions()) != 0 {
		t.Fatal("an unbound consume completed")
	}
	rec = w.do(req{path: routes.MagicLink, fields: map[string]string{routes.FieldToken: token, routes.FieldConfirm: "1"}})
	if rec.Code != http.StatusOK || decode(t, rec)["state"] != "authenticated" {
		t.Fatalf("confirmed consume = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMagicLinkWithAWrongBindIsNotBound(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	w.user("eve@example.com")
	_, token := w.requestLink("ann@example.com", nil)
	eveBind, _ := w.requestLink("eve@example.com", nil)
	rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{eveBind}, fields: map[string]string{routes.FieldToken: token}})
	if decode(t, rec)["state"] != "confirm_required" {
		t.Fatalf("consume with another ceremony's bind = %s", rec.Body.String())
	}
}

func TestMagicLinkIsSingleUse(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	bind, token := w.requestLink("ann@example.com", nil)
	if rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{bind}, fields: map[string]string{routes.FieldToken: token}}); rec.Code != http.StatusOK {
		t.Fatalf("first consume = %d", rec.Code)
	}
	rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{bind}, fields: map[string]string{routes.FieldToken: token}})
	if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "invalid_token" {
		t.Fatalf("second consume = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMagicLinkDiesWithASecurityChange(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	bind, token := w.requestLink("ann@example.com", nil)
	if _, err := w.raw.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	rec := w.do(req{path: routes.MagicLink, cookies: []*http.Cookie{bind}, fields: map[string]string{routes.FieldToken: token}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("consume after an epoch bump = %d %s (C-17)", rec.Code, rec.Body.String())
	}
}

func TestMagicLinkBearerNeedsTheBindField(t *testing.T) {
	w := newWorld(t)
	w.user("ann@example.com")
	rec := w.do(req{path: routes.MagicLinkRequest, bearer: true, fields: map[string]string{routes.FieldIdentifier: "ann@example.com"}})
	bind := decode(t, rec)["bind"]
	if rec.Code != http.StatusAccepted || bind == "" || bindCookie(rec) != nil {
		t.Fatalf("bearer request = %d %s", rec.Code, rec.Body.String())
	}
	token := tokenOf(t, w.waitSent(w.mail, 1)[0].link)
	rec = w.do(req{path: routes.MagicLink, bearer: true, fields: map[string]string{routes.FieldToken: token}})
	if decode(t, rec)["state"] != "confirm_required" {
		t.Fatalf("bearer consume without bind = %s", rec.Body.String())
	}
	rec = w.do(req{path: routes.MagicLink, bearer: true, fields: map[string]string{routes.FieldToken: token, routes.FieldBind: bind}})
	if decode(t, rec)["state"] != "authenticated" {
		t.Fatalf("bearer consume with bind = %s", rec.Body.String())
	}
}

func TestMagicLinkRejectsAMalformedToken(t *testing.T) {
	w := newWorld(t)
	rec := w.do(req{path: routes.MagicLink, fields: map[string]string{routes.FieldToken: "short"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed token = %d", rec.Code)
	}
}
