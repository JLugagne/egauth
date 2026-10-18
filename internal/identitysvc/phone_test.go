package identitysvc_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

func requestPhoneCode(t *testing.T, w *acctWorld, tok, phone string, texts int) (string, string) {
	t.Helper()
	rec := w.call(routes.PhoneVerifyRequest, tok, map[string]string{routes.FieldPhone: phone})
	expectStatus(t, rec, http.StatusOK)
	body := decode(t, rec)
	if body["state"] != "phone_code_sent" || body["handle"] == "" {
		t.Fatalf("body = %v", body)
	}
	msgs := w.waitTexts(texts)
	return body["handle"], msgs[texts-1].Code
}

func TestPhoneVerificationSetsTheVerifiedPhone(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("pam@example.com", goodPass)
	tok := w.login(sub)
	handle, code := requestPhoneCode(t, w, tok, "+33 6 12-34.56 78", 1)
	if got := w.texter.all()[0]; got.To != "+33612345678" || len(code) != 6 {
		t.Fatalf("text = %v", got)
	}
	rec := w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: wrongCode(code)})
	expectStatus(t, rec, http.StatusBadRequest)
	if decode(t, rec)["error"] != "invalid_code" {
		t.Fatalf("body = %s", rec.Body)
	}
	expectStatus(t, w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusOK)
	u := w.user(sub)
	if u.Phone.Value() != "+33612345678" || u.PhoneVerifiedAt.IsZero() {
		t.Fatalf("phone = %q verified %v", u.Phone.Value(), u.PhoneVerifiedAt)
	}
	if !w.sink.has(event.PhoneVerified) {
		t.Fatal("no phone.verified event")
	}
	if countOf(w, event.IdentifierChanged) != 1 {
		t.Fatal("want exactly one identifier.changed event")
	}
	notices := w.amailer.securityNotices()
	if len(notices) != 1 || notices[0].To != "pam@example.com" || notices[0].RevertLink == "" {
		t.Fatalf("notices = %v, want one to the account email", notices)
	}
}

func TestPhoneCodeIsAcceptedOnlyFromTheSubjectItWasSentFor(t *testing.T) {
	w := newAcctWorld(t, nil)
	owner := w.login(w.createVerified("own@example.com", goodPass))
	thief := w.login(w.createVerified("thf@example.com", goodPass))
	handle, code := requestPhoneCode(t, w, owner, "+15550001111", 1)
	expectStatus(t, w.call(routes.PhoneVerify, thief, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusBadRequest)
	expectStatus(t, w.call(routes.PhoneVerify, owner, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusOK)
}

func TestPhoneCodeIsDeletedAfterTooManyWrongCodes(t *testing.T) {
	w := newAcctWorld(t, nil)
	tok := w.login(w.createVerified("try@example.com", goodPass))
	handle, code := requestPhoneCode(t, w, tok, "+15550002222", 1)
	for range ceremony.PhoneVerification.MaxAttempts() {
		w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: wrongCode(code)})
	}
	expectStatus(t, w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusBadRequest)
}

func TestPhoneCodeBoundBeforeASecurityChangeIsDead(t *testing.T) {
	w := newAcctWorld(t, nil)
	sub := w.createVerified("old@example.com", goodPass)
	handle, code := requestPhoneCode(t, w, w.login(sub), "+15550003333", 1)
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	fresh := w.login(sub)
	expectStatus(t, w.call(routes.PhoneVerify, fresh, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusBadRequest)
	if !w.user(sub).Phone.IsZero() {
		t.Fatal("a code bound before a security change set the phone (C-17)")
	}
}

func TestPhoneTakenByAnotherAccountIsRefusedAtVerification(t *testing.T) {
	w := newAcctWorld(t, nil)
	other := w.createVerified("oth@example.com", goodPass)
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, "+15550004444")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.identity.Apply(context.Background(), identity.SetPhone{Subject: other, Phone: phone}); err != nil {
		t.Fatal(err)
	}
	tok := w.login(w.createVerified("me@example.com", goodPass))
	handle, code := requestPhoneCode(t, w, tok, "+15550004444", 1)
	expectStatus(t, w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusConflict)
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

type ceremonyCalls struct {
	ceremony.Store
	mu    sync.Mutex
	calls []string
}

func (c *ceremonyCalls) note(k ceremony.Kind, name string) {
	if k != ceremony.PhoneVerification {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, name)
}

func (c *ceremonyCalls) Consume(ctx context.Context, t principal.TenantID, k ceremony.Kind, h []byte) (ceremony.Record, error) {
	c.note(k, "Consume")
	return c.Store.Consume(ctx, t, k, h)
}

func (c *ceremonyCalls) RecordFailure(ctx context.Context, t principal.TenantID, k ceremony.Kind, h []byte) (int, error) {
	c.note(k, "RecordFailure")
	return c.Store.RecordFailure(ctx, t, k, h)
}

func TestPhoneCodeChargesItsAttemptBeforeItIsCompared(t *testing.T) {
	w := newAcctWorld(t, nil)
	spy := &ceremonyCalls{Store: w.ceremonies}
	w.ceremonies = spy
	w.build()
	tok := w.login(w.createVerified("race@example.com", goodPass))
	handle, code := requestPhoneCode(t, w, tok, "+15550003333", 1)
	expectStatus(t, w.call(routes.PhoneVerify, tok, map[string]string{routes.FieldHandle: handle, routes.FieldCode: code}), http.StatusOK)
	if got := strings.Join(spy.calls, ","); got != "RecordFailure,Consume" {
		t.Fatalf("phone ceremony calls = %s, want RecordFailure,Consume: a code compared before its attempt is charged lets parallel guesses exceed the cap", got)
	}
}
