package identitysvc_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func TestRecoveryEmailIsSetOnlyAfterItsLinkIsConfirmed(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("rae@example.com", goodPass)
	tok := w.login(sub)
	rec := w.call(routes.RecoveryEmail, tok, map[string]string{routes.FieldEmail: "Backup@Example.com"})
	expectStatus(t, rec, http.StatusAccepted)
	link := w.waitKind("recovery_email", 1)[0]
	if link.to != "backup@example.com" {
		t.Fatalf("link sent to %q", link.to)
	}
	if !w.user(sub).RecoveryEmail.IsZero() {
		t.Fatal("recovery email set before confirmation")
	}
	expectStatus(t, w.call(routes.RecoveryEmailConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, link.link)}), http.StatusOK)
	u := w.user(sub)
	if u.RecoveryEmail.Value() != "backup@example.com" || u.RecoveryEmailVerifiedAt.IsZero() {
		t.Fatalf("recovery = %q verified %v", u.RecoveryEmail.Value(), u.RecoveryEmailVerifiedAt)
	}
	if !w.sink.has(event.RecoveryChannelEnrolled) {
		t.Fatal("no recovery_channel.enrolled event")
	}
	if countOf(w, event.IdentifierChanged) != 1 {
		t.Fatal("want exactly one identifier.changed event")
	}
	expectStatus(t, w.call(routes.RecoveryEmailConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, link.link)}), http.StatusBadRequest)
}

func TestRecoveryEmailRefusesThePrimaryAddress(t *testing.T) {
	w := newAcctWorld(t, nil)
	tok := w.login(w.createVerified("rae@example.com", goodPass))
	expectStatus(t, w.call(routes.RecoveryEmail, tok, map[string]string{routes.FieldEmail: "RAE@example.com"}), http.StatusBadRequest)
}

func TestRecoveryEmailLinkBoundBeforeASecurityChangeIsDead(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("rae@example.com", goodPass)
	expectStatus(t, w.call(routes.RecoveryEmail, w.login(sub), map[string]string{routes.FieldEmail: "backup@example.com"}), http.StatusAccepted)
	link := w.waitKind("recovery_email", 1)[0].link
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, w.call(routes.RecoveryEmailConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, link)}), http.StatusBadRequest)
	if !w.user(sub).RecoveryEmail.IsZero() {
		t.Fatal("a link bound before a security change set the recovery email (C-17)")
	}
}
