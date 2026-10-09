package identitysvc_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

func TestAccountDeleteTombstonesAndEndsEverySession(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("del@example.com", goodPass)
	tok, other := w.login(sub), w.login(sub)
	epoch := w.epoch(sub)
	rec := w.call(routes.AccountDelete, tok, map[string]string{})
	expectStatus(t, rec, http.StatusOK)
	if got := decode(t, rec)["state"]; got != "account_deleted" {
		t.Fatalf("state = %q", got)
	}
	if w.user(sub).DeletedAt.IsZero() || w.epoch(sub) <= epoch {
		t.Fatal("the account was not tombstoned behind an epoch bump")
	}
	if w.alive(tok) || w.alive(other) {
		t.Fatal("a session survived the deletion")
	}
	if w.loginStatus("del@example.com", goodPass) != http.StatusUnauthorized {
		t.Fatal("a deleted account still logs in")
	}
	if !w.sink.has(event.AccountDeleted) {
		t.Fatal("no account.deleted event")
	}
}

func TestAccountDeleteRefusesASessionOlderThanTheLastSecurityChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("del@example.com", goodPass)
	tok := w.login(sub)
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	w.sessions.lenient = true
	expectStatus(t, w.call(routes.AccountDelete, tok, map[string]string{}), http.StatusUnauthorized)
	if !w.user(sub).DeletedAt.IsZero() {
		t.Fatal("a stale session deleted the account")
	}
}
