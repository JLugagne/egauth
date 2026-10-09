package identitysvc_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func newUnverifiedAcctWorld(t *testing.T) (*acctWorld, *unverifiedStore) {
	t.Helper()
	var us *unverifiedStore
	w := newAcctWorld(t, func(inner identity.Store) identity.Store {
		us = newUnverifiedStore(inner)
		return us
	})
	return w, us
}

func TestEmailVerifyRequestAnswersUniformlyAndSendsOnlyToUnverified(t *testing.T) {
	w, us := newUnverifiedAcctWorld(t)
	unverified := w.createVerified("una@example.com", goodPass)
	us.setUnverified(unverified)
	w.createVerified("vic@example.com", goodPass)

	var bodies []string
	for _, id := range []string{"una@example.com", "vic@example.com", "nobody@example.com", "not an email"} {
		rec := w.call(routes.EmailVerifyRequest, "", map[string]string{routes.FieldIdentifier: id})
		expectStatus(t, rec, http.StatusAccepted)
		bodies = append(bodies, rec.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("bodies differ: %q vs %q", b, bodies[0])
		}
	}
	w.flush()
	got := w.mailsOf("email_verification")
	if len(got) != 1 || got[0].to != "una@example.com" {
		t.Fatalf("verification mails = %v, want one to una@example.com", got)
	}
}

func TestEmailVerifyProvesOwnershipWipesPreVerificationPasswordAndIsSingleUse(t *testing.T) {
	w, us := newUnverifiedAcctWorld(t)
	sub := w.createVerified("una@example.com", goodPass)
	us.setUnverified(sub)
	expectStatus(t, w.call(routes.EmailVerifyRequest, "", map[string]string{routes.FieldIdentifier: "una@example.com"}), http.StatusAccepted)
	link := w.waitKind("email_verification", 1)[0].link

	rec := w.call(routes.EmailVerify, "", map[string]string{routes.FieldToken: tokenOf(t, link)})
	expectStatus(t, rec, http.StatusOK)
	if got := decode(t, rec)["state"]; got != "email_verified" {
		t.Fatalf("state = %q", got)
	}
	marks := us.marks()
	if len(marks) != 1 || !marks[0].PHC.IsZero() {
		t.Fatalf("marks = %v, want one with no password", marks)
	}
	if w.loginStatus("una@example.com", goodPass) != http.StatusUnauthorized {
		t.Fatal("the pre-verification password survived the proof of ownership (C-39)")
	}
	if !w.sink.has(event.EmailVerified) {
		t.Fatal("no email.verified event")
	}
	expectStatus(t, w.call(routes.EmailVerify, "", map[string]string{routes.FieldToken: tokenOf(t, link)}), http.StatusBadRequest)
}

func TestEmailVerifyLinkBoundBeforeASecurityChangeIsDead(t *testing.T) {
	w, us := newUnverifiedAcctWorld(t)
	sub := w.createVerified("una@example.com", goodPass)
	us.setUnverified(sub)
	expectStatus(t, w.call(routes.EmailVerifyRequest, "", map[string]string{routes.FieldIdentifier: "una@example.com"}), http.StatusAccepted)
	link := w.waitKind("email_verification", 1)[0].link
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, w.call(routes.EmailVerify, "", map[string]string{routes.FieldToken: tokenOf(t, link)}), http.StatusBadRequest)
	if len(us.marks()) != 0 {
		t.Fatal("a link bound before a security change verified the email (C-17)")
	}
}

func TestEmailChangeMovesEmailEndsSessionsAndNotifiesOldAddressWithRevert(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("old@example.com", goodPass)
	tok := w.login(sub)

	rec := w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "New@Example.com"})
	expectStatus(t, rec, http.StatusAccepted)
	change := w.waitKind("email_change", 1)[0]
	if change.to != "new@example.com" {
		t.Fatalf("change link sent to %q, want the new address", change.to)
	}
	if w.user(sub).Email.Value() != "old@example.com" {
		t.Fatal("the email changed before confirmation")
	}
	rec = w.call(routes.EmailChangeConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, change.link)})
	expectStatus(t, rec, http.StatusOK)
	if got := decode(t, rec)["state"]; got != "email_changed" {
		t.Fatalf("state = %q", got)
	}
	if got := w.user(sub).Email.Value(); got != "new@example.com" {
		t.Fatalf("email = %q", got)
	}
	if w.alive(tok) {
		t.Fatal("a session survived the identifier change")
	}
	notices := w.amailer.securityNotices()
	if len(notices) != 1 || notices[0].To != "old@example.com" || notices[0].RevertLink == "" ||
		notices[0].Event != identitysvc.SecurityIdentifierChanged {
		t.Fatalf("notices = %v, want one to the old address with a revert link", notices)
	}
	if w.loginStatus("new@example.com", goodPass) != http.StatusOK || w.loginStatus("old@example.com", goodPass) != http.StatusUnauthorized {
		t.Fatal("login does not follow the new email")
	}
	if !w.sink.has(event.EmailChanged) {
		t.Fatal("no email.changed event")
	}
	expectStatus(t, w.call(routes.EmailChangeConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, change.link)}), http.StatusBadRequest)
}

func TestEmailChangeToAnOwnedAddressSendsAccountExistsInstead(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("me@example.com", goodPass)
	w.createVerified("taken@example.com", goodPass)
	tok := w.login(sub)
	a := w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "taken@example.com"})
	b := w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "free@example.com"})
	expectStatus(t, a, http.StatusAccepted)
	if a.Body.String() != b.Body.String() || a.Code != b.Code {
		t.Fatalf("responses differ: %d %q vs %d %q", a.Code, a.Body, b.Code, b.Body)
	}
	w.flush()
	if got := w.mailsOf("account_exists"); len(got) != 1 || got[0].to != "taken@example.com" {
		t.Fatalf("account_exists = %v", got)
	}
	if got := w.mailsOf("email_change"); len(got) != 1 || got[0].to != "free@example.com" {
		t.Fatalf("email_change = %v, want one to the free address only", got)
	}
}

func TestEmailChangeRefusesUnchangedOrInvalidAddress(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("me@example.com", goodPass)
	tok := w.login(sub)
	expectStatus(t, w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "ME@example.com"}), http.StatusBadRequest)
	expectStatus(t, w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "+33612345678"}), http.StatusBadRequest)
	expectStatus(t, w.call(routes.EmailChange, "", map[string]string{routes.FieldEmail: "x@example.com"}), http.StatusUnauthorized)
}

func TestEmailChangeLinkDiesAfterAPasswordChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("me@example.com", goodPass)
	tok := w.login(sub)
	expectStatus(t, w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "next@example.com"}), http.StatusAccepted)
	link := w.waitKind("email_change", 1)[0].link
	expectStatus(t, w.call(routes.PasswordChange, tok, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass}), http.StatusOK)
	expectStatus(t, w.call(routes.EmailChangeConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, link)}), http.StatusBadRequest)
	if got := w.user(sub).Email.Value(); got != "me@example.com" {
		t.Fatalf("a change link bound before a password change applied (C-17): email = %q", got)
	}
}

func TestResetLinkRequestedBeforeEmailChangeIsRejectedAfterIt(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("me@example.com", goodPass)
	tok := w.login(sub)
	expectStatus(t, w.do(req{path: routes.PasswordForgot, fields: map[string]string{routes.FieldIdentifier: "me@example.com"}}), http.StatusAccepted)
	reset := w.waitKind("reset", 1)[0].link
	expectStatus(t, w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: "next@example.com"}), http.StatusAccepted)
	change := w.waitKind("email_change", 1)[0].link
	expectStatus(t, w.call(routes.EmailChangeConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, change)}), http.StatusOK)
	rec := w.do(req{path: routes.PasswordReset, fields: map[string]string{routes.FieldToken: tokenOf(t, reset), routes.FieldNewPassword: newPass}})
	expectStatus(t, rec, http.StatusBadRequest)
	if w.loginStatus("next@example.com", goodPass) != http.StatusOK {
		t.Fatal("a reset link requested before the email change reset the password (C-17)")
	}
}
