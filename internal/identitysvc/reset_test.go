package identitysvc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

func forgot(w *world, id string) *httptest.ResponseRecorder {
	return w.do(req{path: routes.PasswordForgot, fields: map[string]string{"identifier": id}})
}

func reset(w *world, token, pw string) *httptest.ResponseRecorder {
	return w.do(req{path: routes.PasswordReset, fields: map[string]string{"token": token, "new_password": pw}})
}

func TestForgotIsUniformAndSendsOnlyToVerifiedUsableAccounts(t *testing.T) {
	var unv *unverifiedStore
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		unv = newUnverifiedStore(s)
		return unv
	})
	w.createVerified("known@example.com", goodPass)
	disabled := w.createVerified("disabled@example.com", goodPass)
	if _, err := w.identity.Apply(context.Background(), identity.SetDisabledState{Subject: disabled, Disable: true}); err != nil {
		t.Fatal(err)
	}
	unv.setUnverified(w.createVerified("unverified@example.com", goodPass))
	var first string
	for _, id := range []string{"known@example.com", "nobody@example.com", "disabled@example.com", "unverified@example.com", "not an email", "+33612345678"} {
		rec := forgot(w, id)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d", id, rec.Code)
		}
		if first == "" {
			first = rec.Body.String()
		}
		if rec.Body.String() != first || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("%s: body %q cookies %v", id, rec.Body.String(), rec.Result().Cookies())
		}
	}
	if first != "{\"state\":\"reset_requested\"}\n" {
		t.Fatalf("body = %q", first)
	}
	w.flush()
	msgs := w.mailer.all()
	if len(msgs) != 1 || msgs[0].to != "known@example.com" || msgs[0].kind != "reset" {
		t.Fatalf("deliveries = %+v", msgs)
	}
}

func TestResetSetsThePasswordWithoutASessionAndKeepsFactors(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.createVerified("frank@example.com", goodPass)
	if err := w.passkeys.Save(ctx, passkey.Credential{Subject: sub, ID: passkey.CredentialID("key"), PublicKey: []byte{1}, Discoverable: passkey.Confirmed}); err != nil {
		t.Fatal(err)
	}
	if err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte{1}, AADVersion: mfa.AADVersionCurrent}); err != nil {
		t.Fatal(err)
	}
	forgot(w, "frank@example.com")
	token := tokenOf(t, w.waitMail(1)[0].link)
	epoch := w.epoch(sub)
	rec := reset(w, token, "brand new password")
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"state\":\"password_reset\"}\n" {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body.String())
	}
	if len(w.issuer.admissions()) != 0 || len(rec.Result().Cookies()) != 0 {
		t.Fatal("a password reset issued a session")
	}
	if w.epoch(sub) != epoch+1 {
		t.Fatalf("epoch %d -> %d", epoch, w.epoch(sub))
	}
	items, err := w.identity.PendingOutbox(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var rotated bool
	for _, it := range items {
		rotated = rotated || (it.Subject == sub && it.Event == identity.EventCredentialRotated && it.Rotation == identity.RotationPasswordReset)
	}
	if !rotated {
		t.Fatalf("no CredentialRotated{PasswordReset} outbox row: %+v", items)
	}
	if creds, _ := w.passkeys.List(ctx, sub); len(creds) != 1 {
		t.Fatal("passkeys must survive a reset (I-09)")
	}
	if _, err := w.mfa.GetTOTP(ctx, sub); err != nil {
		t.Fatalf("TOTP must survive a reset (I-09): %v", err)
	}
	if !w.sink.has(event.PasswordReset) {
		t.Fatal("no password.reset event")
	}
	if code, _ := login(w, "frank@example.com", goodPass); code != http.StatusUnauthorized {
		t.Fatal("the old password still works")
	}
	if code, _ := login(w, "frank@example.com", "brand new password"); code != http.StatusOK {
		t.Fatal("the new password does not work")
	}
	if again := reset(w, token, "another new password"); again.Code != http.StatusBadRequest {
		t.Fatalf("a reset link is single use: %d", again.Code)
	}
}

func TestResetRefusedPasswordDoesNotBurnTheLink(t *testing.T) {
	w := newWorld(t)
	w.createVerified("gina@example.com", goodPass)
	forgot(w, "gina@example.com")
	token := tokenOf(t, w.waitMail(1)[0].link)
	if rec := reset(w, token, "short"); rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "password_too_short" {
		t.Fatalf("short = %d %s", rec.Code, rec.Body.String())
	}
	if rec := reset(w, token, "long enough now"); rec.Code != http.StatusOK {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body.String())
	}
}

func TestResetLinkDiesAfterAnySecurityChange(t *testing.T) {
	w := newWorld(t)
	sub := w.createVerified("hank@example.com", goodPass)
	forgot(w, "hank@example.com")
	forgot(w, "hank@example.com")
	msgs := w.waitMail(2)
	first, second := tokenOf(t, msgs[0].link), tokenOf(t, msgs[1].link)
	if rec := reset(w, first, "first new password"); rec.Code != http.StatusOK {
		t.Fatalf("first = %d", rec.Code)
	}
	if rec := reset(w, second, "second new password"); rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "invalid_token" {
		t.Fatalf("a link requested before a reset must die with it (C-17): %d %s", rec.Code, rec.Body.String())
	}
	forgot(w, "hank@example.com")
	third := tokenOf(t, w.waitMail(3)[2].link)
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	if rec := reset(w, third, "third new password"); rec.Code != http.StatusBadRequest {
		t.Fatalf("after a factor change: %d", rec.Code)
	}
	if code, _ := login(w, "hank@example.com", "first new password"); code != http.StatusOK {
		t.Fatal("only the first reset may have applied")
	}
}

func TestResetRedirectsABrowserFormToTheLoginPage(t *testing.T) {
	o, err := redirect.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := redirect.Parse("/signin", o)
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, func(c *identitysvc.Config) { c.LoginPage = page })
	w.createVerified("ivy@example.com", goodPass)
	w.do(req{path: routes.PasswordForgot, form: true, fields: map[string]string{"identifier": "ivy@example.com"}})
	token := tokenOf(t, w.waitMail(1)[0].link)
	rec := w.do(req{path: routes.PasswordReset, form: true, fields: map[string]string{"token": token, "new_password": "new form password"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
		t.Fatalf("reset = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestResetRefusesARegistrationToken(t *testing.T) {
	w := newWorld(t)
	register(w, "jade@example.com", goodPass, false)
	token := tokenOf(t, w.waitMail(1)[0].link)
	if rec := reset(w, token, "new password here"); rec.Code != http.StatusBadRequest || decode(t, rec)["error"] != "invalid_token" {
		t.Fatalf("reset with a registration token = %d %s", rec.Code, rec.Body.String())
	}
}
