package identitysvc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
)

func enrollConfirmedTOTP(t *testing.T, w *acctWorld, sub core.Subject, began time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := w.svc.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	now := w.clock.Now()
	err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte("sealed"), AADVersion: mfa.AADVersionCurrent, CreatedAt: began, ConfirmedAt: &now})
	if err != nil {
		t.Fatal(err)
	}
}

func hasConfirmedTOTP(t *testing.T, w *acctWorld, sub core.Subject) bool {
	t.Helper()
	ok, err := w.mfa.HasConfirmedTOTP(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func revertState(t *testing.T, w *acctWorld, link string) string {
	t.Helper()
	rec := w.call(routes.SecurityRevert, "", map[string]string{routes.FieldToken: tokenOf(t, link)})
	expectStatus(t, rec, http.StatusOK)
	var body struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.State
}

func requireNoResetReachesTheMailbox(t *testing.T, w *acctWorld, email string) {
	t.Helper()
	w.flush()
	expectStatus(t, w.do(req{path: routes.PasswordForgot, fields: map[string]string{routes.FieldIdentifier: email}}), http.StatusAccepted)
	w.flush()
	if got := w.mailsOf("reset"); len(got) != 0 {
		t.Fatalf("a reset link reached the mailbox after a revert removed the last second factor: %v", got)
	}
}

func TestRevertThatRemovesTheLastSecondFactorDisablesTheAccountInsteadOfMailingAReset(t *testing.T) {
	t.Run("totp", func(t *testing.T) {
		w := newAcctWorld(t, nil)
		sub := w.createVerified("owner@example.com", goodPass)
		w.clock.Advance(time.Hour)
		began := w.clock.Now()
		w.clock.Advance(40 * time.Second)
		enrollConfirmedTOTP(t, w, sub, began)
		notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)
		w.clock.Advance(72 * time.Hour)

		if got := revertState(t, w, notice.RevertLink); got != "account_disabled" {
			t.Fatalf("revert answered state %q", got)
		}
		if w.user(sub).DisabledAt.IsZero() {
			t.Fatal("the revert removed the only TOTP and left the account usable from the mailbox alone")
		}
		requireNoResetReachesTheMailbox(t, w, "owner@example.com")
	})
	t.Run("passkey", func(t *testing.T) {
		w := newAcctWorld(t, nil)
		sub := w.createVerified("owner@example.com", goodPass)
		w.clock.Advance(time.Hour)
		addHijackerPasskey(t, w, sub, "only-key")
		notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)
		w.clock.Advance(6 * 24 * time.Hour)

		if got := revertState(t, w, notice.RevertLink); got != "account_disabled" {
			t.Fatalf("revert answered state %q", got)
		}
		if w.user(sub).DisabledAt.IsZero() {
			t.Fatal("the revert removed the only passkey and left the account usable from the mailbox alone")
		}
		requireNoResetReachesTheMailbox(t, w, "owner@example.com")
	})
}

func TestRevertOfAnEarlierNoticeRemovesAFactorEnrolledAfterIt(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	expectStatus(t, w.call(routes.PasswordChange, w.login(sub), map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass}), http.StatusOK)
	rotated := noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)
	w.clock.Advance(48 * time.Hour)
	began := w.clock.Now()
	w.clock.Advance(5 * time.Minute)
	enrollConfirmedTOTP(t, w, sub, began)
	w.clock.Advance(24 * time.Hour)

	if got := revertState(t, w, rotated.RevertLink); got != "account_disabled" {
		t.Fatalf("revert answered state %q", got)
	}
	if hasConfirmedTOTP(t, w, sub) {
		t.Fatal("the revert of a password change kept a TOTP enrolled after it, which a hijacker would keep")
	}
	if w.user(sub).DisabledAt.IsZero() {
		t.Fatal("the revert removed the only second factor and left the account usable from the mailbox alone")
	}
	requireNoResetReachesTheMailbox(t, w, "owner@example.com")
}

func TestRevertOfATOTPNoticeRemovesThatTOTPHoweverSlowlyItWasConfirmed(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	began := w.clock.Now()
	w.clock.Advance(10 * time.Minute)
	enrollConfirmedTOTP(t, w, sub, began)
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)
	w.clock.Advance(time.Hour)

	if got := revertState(t, w, notice.RevertLink); got != "security_reverted" {
		t.Fatalf("revert answered state %q", got)
	}
	if hasConfirmedTOTP(t, w, sub) {
		t.Fatal("the TOTP the notice reported survived its revert because it was confirmed slowly")
	}
	if keys := passkeyIDs(t, w, sub); !keys["owner-key"] {
		t.Fatalf("the revert removed a passkey that predates the reported change: %v", keys)
	}
}

func TestTheRevertOfAnEarlierNoticeRemovesTheHijackersLaterPasskeyAndKeepsTheOwners(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	hijacker := w.login(sub)
	expectStatus(t, w.call(routes.PasswordChange, hijacker, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: hijackPass}), http.StatusOK)
	rotated := noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)
	w.clock.Advance(time.Hour)
	addHijackerPasskey(t, w, sub, "hijacker-key")
	w.clock.Advance(time.Hour)

	if got := revertState(t, w, rotated.RevertLink); got != "security_reverted" {
		t.Fatalf("revert of the password change answered state %q", got)
	}
	if keys := passkeyIDs(t, w, sub); keys["hijacker-key"] || !keys["owner-key"] {
		t.Fatalf("passkeys after the revert = %v, want only the owner's", keys)
	}
	if !w.user(sub).DisabledAt.IsZero() {
		t.Fatal("the owner's own passkey survives, so the account must stay usable")
	}
}

func TestEmailRevertThatRemovesTheLastSecondFactorDisablesTheAccount(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	addHijackerPasskey(t, w, sub, "hijacker-key")
	w.clock.Advance(time.Hour)

	if got := revertState(t, w, ownerNotice.RevertLink); got != "account_disabled" {
		t.Fatalf("revert answered state %q", got)
	}
	u := w.user(sub)
	if u.Email.Value() != "owner@example.com" || u.DisabledAt.IsZero() {
		t.Fatalf("email %q disabled_at %v after the revert", u.Email.Value(), u.DisabledAt)
	}
	if keys := passkeyIDs(t, w, sub); len(keys) != 0 {
		t.Fatalf("passkeys after the revert = %v", keys)
	}
	requireNoResetReachesTheMailbox(t, w, "owner@example.com")
}
