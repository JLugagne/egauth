package identitysvc_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
)

const newPass = "a brand new passphrase"

func TestNewAccountsReportsEveryMissingMember(t *testing.T) {
	w := newWorld(t)
	_, err := identitysvc.NewAccounts(w.svc, identitysvc.AccountsConfig{Phone: true})
	if !errors.Is(err, identitysvc.ErrInvalidAccountsConfig) {
		t.Fatalf("err = %v, want ErrInvalidAccountsConfig", err)
	}
	for _, name := range []string{"Mailer", "Pendings", "Texter", "Sealer"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
	var typedNil *acctMailer
	_, err = identitysvc.NewAccounts(w.svc, identitysvc.AccountsConfig{Mailer: typedNil, Pendings: detachedPendings{clock: w.clock}})
	if err == nil || !strings.Contains(err.Error(), "Mailer") {
		t.Fatalf("typed nil mailer accepted: %v", err)
	}
	if _, err := identitysvc.NewAccounts(nil, identitysvc.AccountsConfig{}); !errors.Is(err, identitysvc.ErrInvalidAccountsConfig) {
		t.Fatalf("nil service accepted: %v", err)
	}
}

func TestAccountsEndpointsMountOnlyEnabledChannels(t *testing.T) {
	w := newAcctWorld(t, nil)
	acc, err := identitysvc.NewAccounts(w.svc, identitysvc.AccountsConfig{Mailer: w.amailer, Pendings: detachedPendings{clock: w.clock}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acc.Endpoints(nil); !errors.Is(err, identitysvc.ErrNilIssuer) {
		t.Fatalf("nil issuer: %v", err)
	}
	eps, err := acc.Endpoints(w.issuer)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range eps {
		paths = append(paths, e.Path)
	}
	slices.Sort(paths)
	want := []string{routes.PasswordChange, routes.SecurityRevert}
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
}

func TestPasswordChangeKeepsCurrentSessionAndEndsOthers(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("ann@example.com", goodPass)
	mine, other := w.login(sub), w.login(sub)
	before := w.sessions.attrsOf(mine)
	epoch := w.epoch(sub)

	rec := w.call(routes.PasswordChange, mine, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass})
	expectStatus(t, rec, http.StatusOK)
	if got := decode(t, rec)["state"]; got != "password_changed" {
		t.Fatalf("state = %q", got)
	}
	if w.epoch(sub) <= epoch {
		t.Fatal("password change did not bump the epoch")
	}
	if !w.alive(mine) {
		t.Fatal("the session that changed the password died")
	}
	if w.alive(other) {
		t.Fatal("another session survived the password change")
	}
	after := w.sessions.attrsOf(mine)
	if after.Lineage() != before.Lineage() || !slices.Equal(after.Factors(), before.Factors()) || after.Epoch() != w.epoch(sub) {
		t.Fatalf("reissued attrs changed lineage or factors, or kept a stale epoch: %v -> %v", before, after)
	}
	if w.loginStatus("ann@example.com", goodPass) != http.StatusUnauthorized {
		t.Fatal("the old password still logs in")
	}
	if w.loginStatus("ann@example.com", newPass) != http.StatusOK {
		t.Fatal("the new password does not log in")
	}
	if !w.sink.has(event.PasswordChanged) {
		t.Fatal("no password.changed event")
	}
}

func TestPasswordChangeRefusesWrongCurrentPasswordAndChargesLockout(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("bob@example.com", goodPass)
	tok := w.login(sub)
	epoch := w.epoch(sub)
	rec := w.call(routes.PasswordChange, tok, map[string]string{routes.FieldPassword: "wrong guess", routes.FieldNewPassword: newPass})
	expectStatus(t, rec, http.StatusUnauthorized)
	if w.epoch(sub) != epoch {
		t.Fatal("a refused change bumped the epoch")
	}
	cred, err := w.identity.GetPassword(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if cred.FailedAttempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", cred.FailedAttempts)
	}
	if w.loginStatus("bob@example.com", goodPass) != http.StatusOK {
		t.Fatal("the password changed despite the refusal")
	}
}

func TestPasswordChangeClearsMustChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("cyd@example.com", goodPass)
	if _, err := w.identity.Apply(context.Background(), identity.SetMustChange{Subject: sub, MustChange: true}); err != nil {
		t.Fatal(err)
	}
	tok := w.login(sub)
	if !w.sessions.attrsOf(tok).MustChangePassword() {
		t.Fatal("precondition: the session must carry must_change")
	}
	rec := w.call(routes.PasswordChange, tok, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass})
	expectStatus(t, rec, http.StatusOK)
	if w.sessions.attrsOf(tok).MustChangePassword() || w.user(sub).MustChange {
		t.Fatal("must_change survived the password change")
	}
}

func TestPasswordChangeRefusesSessionOlderThanTheLastSecurityChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("dan@example.com", goodPass)
	tok := w.login(sub)
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	w.sessions.lenient = true
	rec := w.call(routes.PasswordChange, tok, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass})
	expectStatus(t, rec, http.StatusUnauthorized)
	if w.loginStatus("dan@example.com", goodPass) != http.StatusOK {
		t.Fatal("a stale session changed the password")
	}
}

func TestPasswordChangeRejectsWeakPasswordBeforeAnyChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("eve@example.com", goodPass)
	tok := w.login(sub)
	epoch := w.epoch(sub)
	rec := w.call(routes.PasswordChange, tok, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: "short"})
	expectStatus(t, rec, http.StatusBadRequest)
	if w.epoch(sub) != epoch {
		t.Fatal("a refused password bumped the epoch")
	}
}
