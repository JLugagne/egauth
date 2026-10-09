package identitysvc_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

type flakyPasskeys struct {
	passkey.Store
	fails atomic.Int64
}

func (f *flakyPasskeys) List(ctx context.Context, sub core.Subject) ([]passkey.Credential, error) {
	if f.fails.Add(-1) >= 0 {
		return nil, errors.New("transient passkey store failure")
	}
	return f.Store.List(ctx, sub)
}

func addHijackerPasskey(t *testing.T, w *acctWorld, sub core.Subject, id string) {
	t.Helper()
	if _, err := w.svc.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded}); err != nil {
		t.Fatal(err)
	}
	savePasskey(t, w, sub, id, w.clock.Now())
}

func passkeyIDs(t *testing.T, w *acctWorld, sub core.Subject) map[string]bool {
	t.Helper()
	creds, err := w.passkeys.List(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, c := range creds {
		out[string(c.ID)] = true
	}
	return out
}

func emailOf(t *testing.T, v string) identity.Identifier {
	t.Helper()
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, v)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRevertFromAnIntermediateHijackerAddressIsDeadAfterTheOwnersRevert(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "h1@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, sub, "h2@example.com")
	h1Notice := noticeTo(t, w, "h1@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)

	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("owner revert answered %d", got)
	}
	w.clock.Advance(time.Minute)
	if got := revert(w, h1Notice.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("the intermediate-address revert answered %d after the owner's revert", got)
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" {
		t.Fatalf("email moved to %q after the owner's revert", u.Email.Value())
	}
	w.flush()
	for _, m := range w.mailsOf("reset") {
		if m.to != "owner@example.com" {
			t.Fatalf("a reset link went to %q", m.to)
		}
	}
}

func TestRetriedNoticesAfterARevertCarryNoLiveRestore(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "h1@example.com")
	changedAt := w.clock.Now()
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, sub, "h2@example.com")
	secondAt := w.clock.Now()
	w.clock.Advance(time.Hour)
	revertedAt := w.clock.Now()
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("owner revert answered %d", got)
	}
	w.clock.Advance(time.Minute)

	retries := []identity.OutboxItem{
		{ID: 9001, Component: identity.ComponentNotices, Event: identity.EventIdentifierChanged, Subject: sub,
			Identifier: identity.IdentifierEmail, Old: emailOf(t, "h2@example.com"), CreatedAt: revertedAt},
		{ID: 9002, Component: identity.ComponentNotices, Event: identity.EventIdentifierChanged, Subject: sub,
			Identifier: identity.IdentifierEmail, Old: emailOf(t, "h1@example.com"), CreatedAt: secondAt},
		{ID: 9003, Component: identity.ComponentNotices, Event: identity.EventIdentifierChanged, Subject: sub,
			Identifier: identity.IdentifierEmail, Old: emailOf(t, "owner@example.com"), CreatedAt: changedAt},
	}
	for _, it := range retries {
		before := len(w.amailer.securityNotices())
		if err := w.accounts.SecurityNotice(ctx, it); err != nil {
			t.Fatal(err)
		}
		n := w.amailer.securityNotices()[before]
		if n.RevertLink == "" {
			continue
		}
		if got := revert(w, n.RevertLink); got != http.StatusBadRequest {
			t.Fatalf("a retried notice to %s carried a live revert after the owner's revert (%d)", n.To, got)
		}
		if u := w.user(sub); u.Email.Value() != "owner@example.com" {
			t.Fatalf("a retried notice moved the email to %q", u.Email.Value())
		}
	}
}

func TestEmailRevertRemovesEveryFactorAndIdentifierAddedSince(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)

	addHijackerPasskey(t, w, sub, "hijacker-key")
	if _, err := w.svc.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	if err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte("sealed"), AADVersion: mfa.AADVersionCurrent, CreatedAt: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, "+15550009999")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Apply(ctx, identity.SetPhone{Subject: sub, Phone: phone}); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(time.Hour)

	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("revert answered %d", got)
	}
	keys := passkeyIDs(t, w, sub)
	if keys["hijacker-key"] || !keys["owner-key"] {
		t.Fatalf("passkeys after the email revert = %v, want only the owner's", keys)
	}
	if _, err := w.mfa.GetTOTP(ctx, sub); err == nil {
		t.Fatal("the TOTP enrolled after the reverted email change survived")
	}
	if u := w.user(sub); !u.Phone.IsZero() || u.Email.Value() != "owner@example.com" {
		t.Fatalf("phone %q email %q after the revert", u.Phone.Value(), u.Email.Value())
	}
}

func TestRevertStillCoversAFactorChangeWhoseLinkWasEvicted(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	addHijackerPasskey(t, w, sub, "hijacker-key")
	factorNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)

	hijacker := w.login(sub)
	pass := []string{goodPass, hijackPass, newPass}
	for i := range 6 {
		w.clock.Advance(time.Minute)
		rec := w.call(routes.PasswordChange, hijacker, map[string]string{routes.FieldPassword: pass[i%3], routes.FieldNewPassword: pass[(i+1)%3]})
		expectStatus(t, rec, http.StatusOK)
	}
	w.clock.Advance(time.Hour)
	latest := noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)

	code := revert(w, factorNotice.RevertLink)
	if code != http.StatusOK {
		if got := revert(w, latest.RevertLink); got != http.StatusOK {
			t.Fatalf("no revert the owner holds works: factor %d, latest %d", code, got)
		}
	}
	keys := passkeyIDs(t, w, sub)
	if keys["hijacker-key"] || !keys["owner-key"] {
		t.Fatalf("passkeys after the revert = %v, want only the owner's", keys)
	}
}

func TestRevertFailingMidwayLocksDownAndCanBeRetried(t *testing.T) {
	w := newAcctWorld(t, nil)
	flaky := &flakyPasskeys{Store: w.passkeys}
	w.passkeys = flaky
	w.build()
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	hijacker := w.login(sub)

	flaky.fails.Store(1)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusServiceUnavailable {
		t.Fatalf("revert with a failing passkey store answered %d", got)
	}
	if w.alive(hijacker) {
		t.Fatal("a failed revert left the hijacker's session alive")
	}
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("the retry of a failed revert answered %d: the link was burnt", got)
	}
	u := w.user(sub)
	if u.Email.Value() != "owner@example.com" || !u.MustChange {
		t.Fatalf("email %q must_change %v after the retried revert", u.Email.Value(), u.MustChange)
	}
	if resets := w.waitKind("reset", 1); resets[len(resets)-1].to != "owner@example.com" {
		t.Fatalf("reset sent to %q", resets[len(resets)-1].to)
	}
}

func TestSecurityNoticeRetriesReuseOneRevertLink(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	first := identity.OutboxItem{ID: 41, Component: identity.ComponentNotices, Event: identity.EventCredentialRotated, Subject: sub,
		Rotation: identity.RotationPasswordReset, CreatedAt: w.clock.Now()}
	if err := w.accounts.SecurityNotice(ctx, first); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(time.Minute)
	retried := first
	retried.ID = 42
	retried.CreatedAt = w.clock.Now()
	for range 6 {
		if err := w.accounts.SecurityNotice(ctx, retried); err != nil {
			t.Fatal(err)
		}
	}
	got := w.amailer.securityNotices()
	for _, n := range got[2:] {
		if n.RevertLink != got[1].RevertLink {
			t.Fatal("a retried notice carries a new revert link")
		}
	}
	if code := revert(w, got[0].RevertLink); code != http.StatusOK {
		t.Fatalf("retries of another notice evicted the first revert link (%d)", code)
	}
}

func TestRevertToAnAddressTakenSinceDisablesTheAccount(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	w.createVerified("owner@example.com", goodPass)
	hijacker := w.login(sub)

	if got := revert(w, ownerNotice.RevertLink); got != http.StatusConflict {
		t.Fatalf("revert to a taken address answered %d", got)
	}
	if w.alive(hijacker) {
		t.Fatal("the hijacker's session survived")
	}
	if u := w.user(sub); u.DisabledAt.IsZero() {
		t.Fatal("the account still answers to the hijacker's address: it must be disabled")
	}
	rec := w.do(req{path: routes.PasswordForgot, fields: map[string]string{routes.FieldIdentifier: "hijacker@example.com"}})
	expectStatus(t, rec, http.StatusAccepted)
	w.flush()
	if got := w.mailsOf("reset"); len(got) != 0 {
		t.Fatalf("resets after the refused restore: %v", got)
	}
}

func TestHijackerSelfRevertDoesNotDisarmTheOwnersRevert(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "h1@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, sub, "h2@example.com")
	h1Notice := noticeTo(t, w, "h1@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)

	if got := revert(w, h1Notice.RevertLink); got != http.StatusOK {
		t.Fatalf("hijacker self-revert answered %d", got)
	}
	w.clock.Advance(time.Hour)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("the owner's revert answered %d after the hijacker's self-revert (C-45)", got)
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" {
		t.Fatalf("email %q after the owner's revert", u.Email.Value())
	}
}

func TestAChangeAfterARevertGetsALiveRevert(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "h1@example.com")
	first := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	if got := revert(w, first.RevertLink); got != http.StatusOK {
		t.Fatalf("first revert answered %d", got)
	}
	w.clock.Advance(time.Hour)
	if _, err := w.svc.Apply(context.Background(), identity.SetMustChange{Subject: sub}); err != nil {
		t.Fatal(err)
	}
	hijackEmail(t, w, sub, "h3@example.com")
	second := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	if second.RevertLink == "" || second.RevertLink == first.RevertLink {
		t.Fatal("the change after the revert has no fresh revert link")
	}
	w.clock.Advance(time.Hour)
	if got := revert(w, second.RevertLink); got != http.StatusOK {
		t.Fatalf("the revert of a change made after a revert answered %d", got)
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" {
		t.Fatalf("email %q after the second revert", u.Email.Value())
	}
}

func TestHijackerSelfRevertsCannotWidenASpanOverTheOwnersChange(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "earlier@example.com")
	earlier := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	if got := revert(w, earlier.RevertLink); got != http.StatusOK {
		t.Fatalf("earlier revert answered %d", got)
	}
	w.clock.Advance(time.Hour)
	if _, err := w.svc.Apply(ctx, identity.SetMustChange{Subject: sub}); err != nil {
		t.Fatal(err)
	}
	hijackEmail(t, w, sub, "h1@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	for range 6 {
		if !w.user(sub).DisabledAt.IsZero() {
			break
		}
		w.clock.Advance(time.Hour)
		if _, err := w.svc.Apply(ctx, identity.SetMustChange{Subject: sub}); err != nil {
			t.Fatal(err)
		}
		hijackEmail(t, w, sub, "h2@example.com")
		self := noticeTo(t, w, "h1@example.com", identitysvc.SecurityIdentifierChanged)
		w.clock.Advance(time.Hour)
		if got := revert(w, self.RevertLink); got != http.StatusOK {
			t.Fatalf("hijacker self-revert answered %d", got)
		}
	}
	w.clock.Advance(time.Hour)
	if got := revert(w, ownerNotice.RevertLink); got == http.StatusOK {
		if u := w.user(sub); u.Email.Value() != "owner@example.com" {
			t.Fatalf("email %q after the owner's revert", u.Email.Value())
		}
		return
	}
	u := w.user(sub)
	if u.DisabledAt.IsZero() {
		t.Fatalf("the owner's revert is dead and the account answers to %q: self-reverts disarmed C-45", u.Email.Value())
	}
	w.flush()
	before := len(w.mailsOf("reset"))
	expectStatus(t, w.do(req{path: routes.PasswordForgot, fields: map[string]string{routes.FieldIdentifier: u.Email.Value()}}), http.StatusAccepted)
	w.flush()
	if got := w.mailsOf("reset"); len(got) != before {
		t.Fatalf("a reset reached %q after the account was disabled", got[len(got)-1].to)
	}
}

func TestRevertStillCoversAFactorChangeAfterTheEarliestNoticeExpired(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	expectStatus(t, w.call(routes.PasswordChange, w.login(sub), map[string]string{routes.FieldPassword: goodPass, routes.FieldNewPassword: hijackPass}), http.StatusOK)
	noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)

	w.clock.Advance(7*24*time.Hour - 2*time.Minute)
	addHijackerPasskey(t, w, sub, "hijacker-key")
	factorNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)

	w.clock.Advance(5 * time.Minute)
	hijacker := w.login(sub)
	pass := []string{hijackPass, newPass, goodPass}
	for i := range 6 {
		w.clock.Advance(time.Minute)
		rec := w.call(routes.PasswordChange, hijacker, map[string]string{routes.FieldPassword: pass[i%3], routes.FieldNewPassword: pass[(i+1)%3]})
		expectStatus(t, rec, http.StatusOK)
	}
	w.clock.Advance(time.Hour)
	latest := noticeTo(t, w, "owner@example.com", identitysvc.SecurityCredentialRotated)

	code := revert(w, factorNotice.RevertLink)
	if code != http.StatusOK {
		if got := revert(w, latest.RevertLink); got != http.StatusOK {
			t.Fatalf("no revert the owner holds works: factor %d, latest %d", code, got)
		}
	}
	keys := passkeyIDs(t, w, sub)
	if keys["hijacker-key"] || !keys["owner-key"] {
		t.Fatalf("hijacker passkey survives every revert the owner holds: %v", keys)
	}
}

func TestConcurrentUsesOfOneRevertLinkSucceedOnce(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	token := tokenOf(t, noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged).RevertLink)
	w.clock.Advance(time.Hour)

	const n = 4
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			codes[i] = w.call(routes.SecurityRevert, "", map[string]string{routes.FieldToken: token}).Code
		})
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent uses of one revert link answered %v, want exactly one 200", codes)
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" || !u.MustChange {
		t.Fatalf("email %q must_change %v after the revert", u.Email.Value(), u.MustChange)
	}
	w.waitKind("reset", 1)
	w.flush()
	if got := w.mailsOf("reset"); len(got) != 1 {
		t.Fatalf("%d reset links sent for one revert link", len(got))
	}
}

type hookedPasskeys struct {
	passkey.Store
	hook atomic.Pointer[func()]
}

func (h *hookedPasskeys) List(ctx context.Context, sub core.Subject) ([]passkey.Credential, error) {
	if f := h.hook.Swap(nil); f != nil {
		(*f)()
	}
	return h.Store.List(ctx, sub)
}

type crashingIdentity struct {
	identity.Store
	crashOnEmail atomic.Bool
}

func (c *crashingIdentity) Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	if _, ok := m.(identity.ChangeEmail); ok && c.crashOnEmail.Swap(false) {
		panic("process crash")
	}
	return c.Store.Apply(ctx, m)
}

func setNotices(w *acctWorld, on bool) {
	w.router.mu.Lock()
	defer w.router.mu.Unlock()
	w.router.accounts = nil
	if on {
		w.router.accounts = w.accounts
	}
}

func undeliveredNotice(t *testing.T, w *acctWorld, sub core.Subject, ev identity.Event, at time.Time) identity.OutboxItem {
	t.Helper()
	rows, err := w.identity.PendingOutbox(context.Background(), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rows {
		if it.Subject == sub && it.Component == identity.ComponentNotices && it.Event == ev && it.CreatedAt.Equal(at) {
			return it
		}
	}
	t.Fatalf("no %v notice row at %v", ev, at)
	return identity.OutboxItem{}
}

func deliverLate(t *testing.T, w *acctWorld, item identity.OutboxItem) identitysvc.SecurityNoticeMessage {
	t.Helper()
	before := len(w.amailer.securityNotices())
	if err := w.accounts.SecurityNotice(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	got := w.amailer.securityNotices()
	if len(got) != before+1 {
		t.Fatalf("late delivery sent %d notices", len(got)-before)
	}
	return got[before]
}

func TestDelayedFactorNoticeGoesToTheAddressOfItsTimeAndIsCoveredByTheOwnersRevert(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)

	setNotices(w, false)
	enrolledAt := w.clock.Now()
	addHijackerPasskey(t, w, sub, "hijacker-key")
	setNotices(w, true)
	w.clock.Advance(10 * time.Minute)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)

	late := deliverLate(t, w, undeliveredNotice(t, w, sub, identity.EventFactorsChanged, enrolledAt))
	if late.To != "owner@example.com" {
		t.Fatalf("delayed factor notice went to %s, the address that replaced the owner's", late.To)
	}
	w.clock.Advance(time.Hour)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("owner revert answered %d", got)
	}
	if keys := passkeyIDs(t, w, sub); keys["hijacker-key"] || !keys["owner-key"] {
		t.Fatalf("hijacker passkey enrolled before the email change, notified late, survives the owner's revert: %v", keys)
	}
}

func TestDelayedNoticeWithoutEmailHistoryArmsNoLinkAtTheNewAddress(t *testing.T) {
	w := newAcctWorld(t, nil)
	ctx := context.Background()
	sub := w.createVerified("owner@example.com", goodPass)
	w.clock.Advance(24 * time.Hour)

	setNotices(w, false)
	enrolledAt := w.clock.Now()
	addHijackerPasskey(t, w, sub, "hijacker-key")
	w.clock.Advance(10 * time.Minute)
	if _, err := w.svc.Apply(ctx, identity.ChangeEmail{Subject: sub, Email: emailOf(t, "hijacker@example.com")}); err != nil {
		t.Fatal(err)
	}
	setNotices(w, true)

	late := deliverLate(t, w, undeliveredNotice(t, w, sub, identity.EventFactorsChanged, enrolledAt))
	if late.RevertLink != "" {
		t.Fatalf("a late notice of a change made under an unknown former address armed a revert link at %s", late.To)
	}
}

func TestAChangeRightAfterARevertIsRevertible(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("owner@example.com", goodPass)
	savePasskey(t, w, sub, "owner-key", w.clock.Now())
	w.clock.Advance(24 * time.Hour)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("owner revert answered %d", got)
	}

	w.clock.Advance(30 * time.Second)
	addHijackerPasskey(t, w, sub, "late-key")
	n := noticeTo(t, w, "owner@example.com", identitysvc.SecurityFactorsChanged)
	if n.RevertLink == "" {
		t.Fatalf("a factor added 30s after a revert is neither reverted (%v) nor revertible", passkeyIDs(t, w, sub))
	}
	w.clock.Advance(time.Minute)
	if got := revert(w, n.RevertLink); got != http.StatusOK {
		t.Fatalf("revert of a change made right after a revert answered %d", got)
	}
	if keys := passkeyIDs(t, w, sub); keys["late-key"] || !keys["owner-key"] {
		t.Fatalf("passkeys after the second revert = %v", keys)
	}
}

func TestRevertLinksOfOneAccountAreSerialized(t *testing.T) {
	w := newAcctWorld(t, nil)
	hooked := &hookedPasskeys{Store: w.passkeys}
	w.passkeys = hooked
	w.build()
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "h1@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)
	hijackEmail(t, w, sub, "h2@example.com")
	h1Notice := noticeTo(t, w, "h1@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)

	nested := 0
	race := func() { nested = revert(w, h1Notice.RevertLink) }
	hooked.hook.Store(&race)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("owner revert answered %d", got)
	}
	if nested == 0 {
		t.Fatal("the racing revert never ran")
	}
	if nested == http.StatusOK {
		t.Fatal("a second revert link ran while the owner's revert of the same account was in progress")
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" {
		t.Fatalf("email %q after the owner's revert raced a hijacker revert", u.Email.Value())
	}
	w.clock.Advance(time.Minute)
	if got := revert(w, h1Notice.RevertLink); got != http.StatusBadRequest {
		t.Fatalf("the hijacker revert answered %d after the owner's revert", got)
	}
}

func TestRevertInterruptedByACrashKeepsItsLink(t *testing.T) {
	var crashing *crashingIdentity
	w := newAcctWorld(t, func(s identity.Store) identity.Store {
		crashing = &crashingIdentity{Store: s}
		return crashing
	})
	sub := w.createVerified("owner@example.com", goodPass)
	hijackEmail(t, w, sub, "hijacker@example.com")
	ownerNotice := noticeTo(t, w, "owner@example.com", identitysvc.SecurityIdentifierChanged)
	w.clock.Advance(time.Hour)

	crashing.crashOnEmail.Store(true)
	func() {
		defer func() { _ = recover() }()
		revert(w, ownerNotice.RevertLink)
	}()
	if crashing.crashOnEmail.Load() {
		t.Fatal("the revert never reached the restore")
	}
	w.clock.Advance(2 * time.Minute)
	if got := revert(w, ownerNotice.RevertLink); got != http.StatusOK {
		t.Fatalf("the owner's link answered %d after a crash between the lockdown and the restore", got)
	}
	if u := w.user(sub); u.Email.Value() != "owner@example.com" {
		t.Fatalf("email %q after the retried revert", u.Email.Value())
	}
}
