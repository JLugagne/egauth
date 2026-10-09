package identitysvc_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

const hijackPass = "the hijacker passphrase"

func noticeTo(t *testing.T, w *acctWorld, to string, ev identitysvc.SecurityEvent) identitysvc.SecurityNoticeMessage {
	t.Helper()
	var found []identitysvc.SecurityNoticeMessage
	for _, n := range w.amailer.securityNotices() {
		if n.To == to && n.Event == ev {
			found = append(found, n)
		}
	}
	if len(found) == 0 {
		t.Fatalf("no %d notice to %s in %v", ev, to, w.amailer.securityNotices())
	}
	return found[len(found)-1]
}

func hijackEmail(t *testing.T, w *acctWorld, sub core.Subject, to string) {
	t.Helper()
	tok := w.login(sub)
	n := len(w.mailsOf("email_change"))
	expectStatus(t, w.call(routes.EmailChange, tok, map[string]string{routes.FieldEmail: to}), http.StatusAccepted)
	link := w.waitKind("email_change", n+1)[n].link
	expectStatus(t, w.call(routes.EmailChangeConfirm, "", map[string]string{routes.FieldToken: tokenOf(t, link)}), http.StatusOK)
}

func revert(w *acctWorld, link string) int {
	w.t.Helper()
	return w.call(routes.SecurityRevert, "", map[string]string{routes.FieldToken: tokenOf(w.t, link)}).Code
}

func TestRevertOfEmailChangeRestoresTheAddressAndLocksTheHijackerOut(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)

	w.clock.Advance(time.Hour)
	hijacker := w.login(sub)
	expectStatus(t, w.call(routes.PasswordChange, hijacker, map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: hijackPass}), http.StatusOK)
	hijackerNotice := noticeTo(t, w, "hijacker@example.com", identitysvc.SecurityCredentialRotated)
	epoch := w.epoch(sub)

	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("revert after a later security change answered %d; a later change must not disarm it (C-45)", got)
	}
	u := w.user(sub)
	if u.Email.Value() != "owner@example.com" || !u.MustChange || w.epoch(sub) <= epoch {
		t.Fatalf("email %q must_change %v epoch %d->%d", u.Email.Value(), u.MustChange, epoch, w.epoch(sub))
	}
	if w.alive(hijacker) {
		t.Fatal("the hijacker's session survived the revert")
	}
	for _, p := range []string{goodPass, hijackPass} {
		if w.loginStatus("owner@example.com", p) != http.StatusUnauthorized {
			t.Fatalf("password %q still logs in after the revert", p)
		}
	}
	resets := w.waitKind("reset", 1)
	if resets[0].to != "owner@example.com" {
		t.Fatalf("reset link sent to %q, want the restored address", resets[0].to)
	}
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("a consumed revert link answered %d", got)
	}
	if got := revert(w, hijackerNotice.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("the hijacker's revert link answered %d after the owner's revert", got)
	}
	pingPong := noticeTo(t, w, "hijacker@example.com", identitysvc.SecurityIdentifierChanged)
	if got := revert(w, pingPong.RevertLink); got != http.StatusBadRequest || w.user(sub).Email.Value() != "owner@example.com" {
		t.Fatalf("the restore's notice to the hijacker's address carried a live revert link (%d)", got)
	}
	rec := w.do(req{path: routes.PasswordReset, fields: map[string]string{routes.FieldToken: tokenOf(t, resets[0].link), routes.FieldNewPassword: newPass}})
	expectStatus(t, rec, http.StatusOK)
	if w.loginStatus("owner@example.com", newPass) != http.StatusOK {
		t.Fatal("the owner cannot log in after resetting")
	}
	if !w.sink.has(event.AccountLocked) {
		t.Fatal("no account.locked event for the revert")
	}
}

func TestRevertBoundToAnAddressTheAccountNoLongerUsesIsRefusedWithoutConsumingIt(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	expectStatus(t, w.call(routes.PasswordChange, w.login(sub), map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: newPass}), http.StatusOK)
	rotated := noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)
	hijackEmail(t, w, sub, "hijacker@example.com")
	changed := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)

	if got := revert(w, rotated.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("a credential revert bound to a former address answered %d", got)
	}
	if w.user(sub).Email.Value() != "hijacker@example.com" || len(w.mailsOf("reset")) != 0 {
		t.Fatal("a refused revert changed the account or sent a reset")
	}
	h, err := ceremonycodec.ParseHandle(tokenOf(t, rotated.RevertLink))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ceremonies.Peek(context.Background(), sub.Tenant, ceremony.SecurityRevert, h.Hash()); err != nil {
		t.Fatalf("the refused revert was consumed: %v", err)
	}
	if got := revert(w, changed.RevertLink); got != http.StatusOK {
		t.Fatalf("email revert answered %d", got)
	}
	if got := revert(w, rotated.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("a revert of a change the email revert already covered answered %d", got)
	}
}

func TestRevertOfFactorsChangedRemovesOnlyWhatWasAddedSince(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)

	if _, err := w.svc.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	savePasskey(t, w, sub, "hijacker-key", w.clock.Now())
	if err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte("sealed"), AADVersion: mfa.AADVersionCurrent, CreatedAt: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)
	w.clock.Advance(time.Hour)

	if got := revert(w, notice.RevertLink); got != http.StatusOK {
		t.Fatalf("revert answered %d", got)
	}
	creds, err := w.passkeys.List(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || string(creds[0].ID) != "owner-key" {
		t.Fatalf("passkeys after revert = %v, want only the owner's", creds)
	}
	if _, err := w.mfa.GetTOTP(ctx, sub); err == nil {
		t.Fatal("the TOTP enrolled after the reported change survived the revert")
	}
	if !w.user(sub).MustChange {
		t.Fatal("must_change not set")
	}
}

func TestRevertOfPhoneChangeRemovesThePhoneAndKeepsTheEmail(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, "+15550009999")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Apply(context.Background(), identity.SetPhone{Subject: sub, Phone: phone}); err != nil {
		t.Fatal(err)
	}
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	if got := revert(w, notice.RevertLink); got != http.StatusOK {
		t.Fatalf("revert answered %d", got)
	}
	u := w.user(sub)
	if !u.Phone.IsZero() || u.Email.Value() != "owner@example.com" || !u.MustChange {
		t.Fatalf("phone %q email %q must_change %v", u.Phone.Value(), u.Email.Value(), u.MustChange)
	}
}

func TestSecurityNoticeSkipsRowsThatNeedNoNotice(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	ctx := context.Background()
	at := w.clock.Now()
	for _, it := range []identity.OutboxItem{
		{ID: 1, Component: identity.ComponentSessions, Event: identity.EventCredentialRotated, Subject: sub, Rotation: identity.RotationPasswordReset, CreatedAt: at},
		{ID: 2, Component: identity.ComponentNotices, Event: identity.EventCredentialRotated, Subject: sub, Rotation: identity.RotationSecurityRevert, CreatedAt: at},
		{ID: 3, Component: identity.ComponentNotices, Event: identity.EventIdentifierChanged, Subject: sub, Identifier: identity.IdentifierEmail, CreatedAt: at},
		{ID: 4, Component: identity.ComponentNotices, Event: identity.EventDisable, Subject: sub, CreatedAt: at},
		{ID: 5, Component: identity.ComponentNotices, Event: identity.EventDelete, Subject: sub, CreatedAt: at},
		{ID: 6, Component: identity.ComponentNotices, Event: identity.EventCredentialRotated, Subject: core.Subject{Tenant: sub.Tenant, User: uuid.New()},
			Rotation: identity.RotationPasswordReset, CreatedAt: at},
	} {
		if err := w.accounts.SecurityNotice(ctx, it); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.amailer.securityNotices(); len(got) != 0 {
		t.Fatalf("notices = %v, want none", got)
	}
}

func TestSecurityNoticeIsStableAcrossRetriesAndHasNoRevertPastItsLifetime(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	ctx := context.Background()
	item := identity.OutboxItem{ID: 42, Component: identity.ComponentNotices, Event: identity.EventCredentialRotated, Subject: sub,
		Rotation: identity.RotationPasswordReset, CreatedAt: w.clock.Now()}
	for range 2 {
		if err := w.accounts.SecurityNotice(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	got := w.amailer.securityNotices()
	if len(got) != 2 || got[0].DeliveryID != got[1].DeliveryID || got[0].RevertLink == "" {
		t.Fatalf("notices = %v, want two with one DeliveryID and a revert link", got)
	}
	if got[0].Summary == "" || !got[0].OccurredAt.Equal(item.CreatedAt) {
		t.Fatalf("notice = %+v", got[0])
	}
	old := item
	old.ID = 43
	old.CreatedAt = w.clock.Now().Add(-ceremony.SecurityRevert.TTL() - time.Minute)
	if err := w.accounts.SecurityNotice(ctx, old); err != nil {
		t.Fatal(err)
	}
	if late := w.amailer.securityNotices()[2]; late.RevertLink != "" {
		t.Fatal("a notice past the revert lifetime carries a revert link")
	}
}

func TestRevertLinkExpiresSevenDaysAfterTheChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(ceremony.SecurityRevert.TTL() + time.Second)
	if got := revert(w, notice.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("an expired revert answered %d", got)
	}
}

func savePasskey(t *testing.T, w *acctWorld, sub core.Subject, id string, at time.Time) {
	t.Helper()
	err := w.passkeys.Save(context.Background(), passkey.Credential{
		Subject: sub, ID: passkey.CredentialID(id), PublicKey: []byte("pk"), CreatedAt: at, Discoverable: passkey.Confirmed,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func identifierKinds() []ceremony.Kind {
	var kinds []ceremony.Kind
	for _, k := range ceremony.All() {
		if k.Scope() == ceremony.Identifier {
			kinds = append(kinds, k)
		}
	}
	return kinds
}

func eraseRevertScopes(t *testing.T, w *acctWorld, sub core.Subject, current string) (total int64) {
	t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, current)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scopes, err := w.accounts.RevertScopes(ctx, sub, []identity.Identifier{id})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range scopes {
		n, err := w.ceremonies.DeleteForScope(ctx, sub.Tenant, s.Hash(), identifierKinds()...)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

func TestRevertScopesLeavePreviousAddressLinksToTheirTTL(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	if eraseRevertScopes(t, w, sub, "hijacker@example.com") == 0 {
		t.Fatal("the tenure, anchor and span bookkeeping was not reachable")
	}
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("the link at the previous address is per address, not per subject, and must survive: %d", got)
	}
}

func TestDeletingAnAccountKeepsTheRevertLinkOfAnotherAccountAtAReusedAddress(t *testing.T) {
	w := newAcctWorld(t, nil)
	a := w.createVerified("shared@example.com", goodPass)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, a, "a-new@example.com")
	w.clock.Advance(time.Hour)
	b := w.createVerified("shared@example.com", goodPass)
	hijackEmail(t, w, b, "hijacker@example.com")
	link := noticeTo(t, w, "shared@example.com", identitysvc.SecurityIdentifierChanged).RevertLink
	eraseRevertScopes(t, w, a, "a-new@example.com")
	if got := revert(w, link); got != http.StatusOK {
		t.Fatalf("deleting account A erased the revert link of account B: %d", got)
	}
}

func TestRevertInADeploymentWithoutPasswordResetSendsNoResetAndNoFailure(t *testing.T) {
	w := newAcctWorld(t, nil)
	w.noReset = true
	w.build()
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	notice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)

	if got := revert(w, notice.RevertLink); got != http.StatusOK {
		t.Fatalf("revert answered %d", got)
	}
	_ = w.svc.Close()
	if n := len(w.mailsOf("reset")); n != 0 {
		t.Fatalf("%d reset links sent by a deployment that has no reset page", n)
	}
	if w.sink.has(event.DeliveryFailed) {
		t.Fatal("a revert raised delivery.failed in a deployment without password reset")
	}
}
