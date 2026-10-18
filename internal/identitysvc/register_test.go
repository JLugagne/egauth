package identitysvc_test

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

func register(w *world, email, pw string, bearer bool) *httptest.ResponseRecorder {
	return w.do(req{path: routes.Register, bearer: bearer, fields: map[string]string{"identifier": email, "password": pw}})
}

func confirm(w *world, token string, fields map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	f := map[string]string{"token": token}
	maps.Copy(f, fields)
	return w.do(req{path: routes.RegisterConfirm, fields: f, cookies: cookies})
}

func cookieShape(rec *httptest.ResponseRecorder) []string {
	var out []string
	for _, c := range rec.Result().Cookies() {
		out = append(out, c.Name+"|"+c.Path+"|"+c.Domain+"|"+string(rune('0'+c.SameSite)))
	}
	return out
}

func TestRegisterIsUniformForExistingAndUnknownEmails(t *testing.T) {
	w := newWorld(t)
	w.createVerified("taken@example.com", goodPass)
	known := register(w, "taken@example.com", goodPass, false)
	unknown := register(w, "fresh@example.com", goodPass, false)
	if known.Code != http.StatusAccepted || unknown.Code != known.Code {
		t.Fatalf("status known=%d unknown=%d", known.Code, unknown.Code)
	}
	if known.Body.String() != unknown.Body.String() || known.Body.String() != "{\"state\":\"registration_requested\"}\n" {
		t.Fatalf("bodies differ: %q vs %q", known.Body.String(), unknown.Body.String())
	}
	if bindCookie(known) == nil || !slices.Equal(cookieShape(known), cookieShape(unknown)) {
		t.Fatalf("cookies differ: %v vs %v", cookieShape(known), cookieShape(unknown))
	}
	msgs := w.waitMail(2)
	kinds := map[string]string{}
	for _, m := range msgs {
		kinds[m.to] = m.kind
	}
	if kinds["taken@example.com"] != "account_exists" || kinds["fresh@example.com"] != "registration" {
		t.Fatalf("deliveries = %+v", msgs)
	}
	if hashes := w.hasher.hashes.Load(); hashes < 3 {
		t.Fatalf("the password must be hashed for both identifiers, got %d hashes", hashes)
	}
	id, _ := identity.NewIdentifier(identity.IdentifierEmail, "fresh@example.com")
	if _, err := w.identity.FindUser(context.Background(), core.TenantID{}, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an account exists before the email is verified: %v", err)
	}
}

func TestRegisterUnderBearerReturnsABindForBothBranches(t *testing.T) {
	w := newWorld(t)
	w.createVerified("taken@example.com", goodPass)
	known := decode(t, register(w, "taken@example.com", goodPass, true))
	unknown := decode(t, register(w, "fresh@example.com", goodPass, true))
	if known["state"] != "registration_requested" || len(known["bind"]) != 43 || len(unknown["bind"]) != 43 || len(known) != len(unknown) {
		t.Fatalf("bodies %v vs %v", known, unknown)
	}
}

func TestRegisterRefusesBeforeAnyLookup(t *testing.T) {
	w := newWorld(t)
	w.createVerified("taken@example.com", goodPass)
	for _, c := range []struct{ id, pw, code string }{
		{"taken@example.com", "short", "password_too_short"},
		{"fresh@example.com", "short", "password_too_short"},
		{"+33612345678", goodPass, "invalid_identifier"},
		{"nope", goodPass, "invalid_identifier"},
	} {
		rec := register(w, c.id, c.pw, false)
		if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != c.code {
			t.Errorf("%s/%s = %d %s", c.id, c.pw, rec.Code, rec.Body.String())
		}
	}
	w.flush()
	if n := len(w.mailer.all()); n != 0 {
		t.Fatalf("%d messages sent for refused registrations", n)
	}
}

func TestConfirmBoundCreatesAVerifiedAccountAndAdmitsWithEmailLink(t *testing.T) {
	w := newWorld(t)
	reg := register(w, "Bob@Example.com", goodPass, false)
	token := tokenOf(t, w.waitMail(1)[0].link)
	rec := confirm(w, token, nil, bindCookie(reg))
	if rec.Code != http.StatusOK || decode(t, rec)["state"] != "authenticated" {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	adm := w.issuer.admissions()
	if len(adm) != 1 || !slices.Equal(adm[0].factors, []core.Factor{core.FactorEmailLink}) {
		t.Fatalf("admissions = %+v", adm)
	}
	u, err := w.identity.GetUser(context.Background(), adm[0].subject)
	if err != nil || u.EmailVerifiedAt.IsZero() || u.Email.Value() != "bob@example.com" {
		t.Fatalf("account = %+v %v", u, err)
	}
	if code, body := login(w, "bob@example.com", goodPass); code != http.StatusOK {
		t.Fatalf("login with the registered password = %d %s", code, body)
	}
	if again := confirm(w, token, nil, bindCookie(reg)); again.Code != http.StatusBadRequest || decode(t, again)["error"] != "invalid_token" {
		t.Fatalf("second confirm = %d %s", again.Code, again.Body.String())
	}
}

func TestConfirmUnderBearerUsesTheBindField(t *testing.T) {
	w := newWorld(t)
	bind := decode(t, register(w, "carol@example.com", goodPass, true))["bind"]
	token := tokenOf(t, w.waitMail(1)[0].link)
	rec := confirm(w, token, map[string]string{"bind": bind})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if code, _ := login(w, "carol@example.com", goodPass); code != http.StatusOK {
		t.Fatal("bound bearer confirmation must keep the password")
	}
}

func TestConfirmInAnotherBrowserNeedsAnInterstitialAndDropsThePassword(t *testing.T) {
	w := newWorld(t)
	register(w, "victim@example.com", "attacker chosen pw", false)
	token := tokenOf(t, w.waitMail(1)[0].link)
	rec := confirm(w, token, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"state\":\"confirm_required\",\"account_hint\":\"v***@example.com\"}\n" {
		t.Fatalf("interstitial = %d %s", rec.Code, rec.Body.String())
	}
	wrong := confirm(w, token, nil, &http.Cookie{Name: "__Host-egauth_bind", Value: "forged"})
	if decode(t, wrong)["state"] != "confirm_required" {
		t.Fatalf("a wrong bind is no bind: %s", wrong.Body.String())
	}
	if len(w.issuer.admissions()) != 0 {
		t.Fatal("the interstitial admitted a session")
	}
	ok := confirm(w, token, map[string]string{"confirm": "1"})
	if ok.Code != http.StatusOK || decode(t, ok)["state"] != "authenticated" {
		t.Fatalf("explicit confirm = %d %s", ok.Code, ok.Body.String())
	}
	if code, _ := login(w, "victim@example.com", "attacker chosen pw"); code != http.StatusUnauthorized {
		t.Fatal("a password chosen in another browser must not survive an unbound confirmation (C-39)")
	}
}

func TestConfirmWipesAnUnverifiedAccountsCredentials(t *testing.T) {
	var unv *unverifiedStore
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		unv = newUnverifiedStore(s)
		return unv
	})
	ctx := context.Background()
	pre := w.createVerified("owner@example.com", "attacker password")
	unv.setUnverified(pre)
	if err := w.passkeys.Save(ctx, passkey.Credential{Subject: pre, ID: passkey.CredentialID("attacker-key"), PublicKey: []byte{1}, Discoverable: passkey.Confirmed}); err != nil {
		t.Fatal(err)
	}
	if err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: pre, Sealed: []byte{1}, AADVersion: mfa.AADVersionCurrent}); err != nil {
		t.Fatal(err)
	}
	epoch := w.epoch(pre)
	reg := register(w, "owner@example.com", goodPass, false)
	msgs := w.waitMail(1)
	if msgs[0].kind != "registration" {
		t.Fatalf("an unverified account must get a registration link, got %+v", msgs)
	}
	rec := confirm(w, tokenOf(t, msgs[0].link), nil, bindCookie(reg))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if adm := w.issuer.admissions(); len(adm) != 1 || adm[0].subject != pre {
		t.Fatalf("admissions = %+v", adm)
	}
	if creds, _ := w.passkeys.List(ctx, pre); len(creds) != 0 {
		t.Fatalf("pre-verification passkeys survived: %d", len(creds))
	}
	if _, err := w.mfa.GetTOTP(ctx, pre); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pre-verification TOTP survived: %v", err)
	}
	marks := unv.marks()
	if len(marks) != 1 || marks[0].PHC.PHC() != "$fake$"+goodPass {
		t.Fatalf("MarkEmailVerified = %+v", marks)
	}
	if w.epoch(pre) < epoch+3 {
		t.Fatalf("epoch %d -> %d: each wipe step must bump", epoch, w.epoch(pre))
	}
	if code, _ := login(w, "owner@example.com", "attacker password"); code != http.StatusUnauthorized {
		t.Fatal("the pre-hijacker's password survived")
	}
	if code, _ := login(w, "owner@example.com", goodPass); code != http.StatusOK {
		t.Fatal("the owner's password must work")
	}
}

func TestConfirmRefusesAnEmailVerifiedMeanwhile(t *testing.T) {
	w := newWorld(t)
	reg := register(w, "race@example.com", goodPass, false)
	token := tokenOf(t, w.waitMail(1)[0].link)
	w.createVerified("race@example.com", "other password")
	rec := confirm(w, token, nil, bindCookie(reg))
	if rec.Code != http.StatusConflict || decode(t, rec)["error"] != "account_exists" {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if len(w.issuer.admissions()) != 0 {
		t.Fatal("admitted into an account the link never proved")
	}
}

func TestConfirmRefusesUnknownExpiredAndForeignTokens(t *testing.T) {
	w := newWorld(t)
	w.createVerified("dave@example.com", goodPass)
	w.do(req{path: routes.PasswordForgot, fields: map[string]string{"identifier": "dave@example.com"}})
	reset := tokenOf(t, w.waitMail(1)[0].link)
	reg := register(w, "erin@example.com", goodPass, false)
	msgs := w.waitMail(2)
	var regToken string
	for _, m := range msgs {
		if m.kind == "registration" {
			regToken = tokenOf(t, m.link)
		}
	}
	for name, token := range map[string]string{"malformed": "abc", "unknown": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "reset kind": reset} {
		rec := confirm(w, token, nil, bindCookie(reg))
		if rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "invalid_token" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	w.clock.Advance(ceremony.PendingRegistration.TTL() + time.Second)
	if rec := confirm(w, regToken, nil, bindCookie(reg)); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired link: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterIsUniformWhenTheCeremonyStoreFails(t *testing.T) {
	cer := &countingCeremonies{putErr: errors.New("pool exhausted")}
	w := newWorld(t, func(c *identitysvc.Config) {
		cer.Store = c.Ceremonies
		c.Ceremonies = cer
	})
	w.createVerified("taken@example.com", goodPass)
	known := register(w, "taken@example.com", goodPass, false)
	unknown := register(w, "fresh@example.com", goodPass, false)
	if known.Code != http.StatusAccepted || unknown.Code != known.Code || known.Body.String() != unknown.Body.String() {
		t.Fatalf("a ceremony store outage tells verified accounts apart: known=%d %q unknown=%d %q",
			known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
	if !slices.Equal(cookieShape(known), cookieShape(unknown)) {
		t.Fatalf("cookies differ: %v vs %v", cookieShape(known), cookieShape(unknown))
	}
	if !w.sink.has(event.DeliveryFailed) {
		t.Fatal("a dropped registration must be reported as DeliveryFailed")
	}
}

func TestRegisterTouchesTheCeremonyStoreTheSameWayForBothBranches(t *testing.T) {
	cer := &countingCeremonies{}
	w := newWorld(t, func(c *identitysvc.Config) {
		cer.Store = c.Ceremonies
		c.Ceremonies = cer
	})
	w.createVerified("taken@example.com", goodPass)
	register(w, "taken@example.com", goodPass, false)
	known := cer.puts.Load()
	register(w, "fresh@example.com", goodPass, false)
	if unknown := cer.puts.Load() - known; known != 1 || unknown != 1 {
		t.Fatalf("ceremony writes known=%d unknown=%d; both branches must write once", known, unknown)
	}
	msgs := w.waitMail(2)
	kinds := map[string]string{}
	for _, m := range msgs {
		kinds[m.to] = m.kind
	}
	if len(msgs) != 2 || kinds["taken@example.com"] != "account_exists" || kinds["fresh@example.com"] != "registration" {
		t.Fatalf("deliveries = %+v", msgs)
	}
}
