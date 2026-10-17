package flow_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/flow"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/webauthntest"
)

var _ flow.Passwords = (*identitysvc.Service)(nil)

func (w *world) passkeySession(email, password string, a *webauthntest.Authenticator) *client {
	w.t.Helper()
	c := w.native()
	rec := c.login(email, password, nil)
	expect(w.t, rec, http.StatusOK)
	expect(w.t, c.finishStepUp(a, decode[journeyBody](w.t, rec).Flow), http.StatusOK)
	w.clock.Advance(30 * time.Second)
	w.sink.reset()
	return c
}

func (c *client) beginPasskeyReauth() passkeyChallenge {
	c.w.t.Helper()
	rec := c.post(routes.Reauth, map[string]any{routes.FieldFactor: "passkey"})
	expect(c.w.t, rec, http.StatusOK)
	ch := decode[passkeyChallenge](c.w.t, rec)
	if ch.State != "passkey_challenge" || ch.Handle == "" || len(ch.Options) == 0 {
		c.w.t.Fatalf("challenge %+v", ch)
	}
	return ch
}

func (c *client) finishPasskeyReauth(a *webauthntest.Authenticator, ch passkeyChallenge, extra map[string]any) *httptest.ResponseRecorder {
	c.w.t.Helper()
	body := map[string]any{}
	must(c.w.t, json.Unmarshal(a.Login(c.w.t, ch.Options), &body))
	body[routes.FieldFactor] = "passkey"
	body[routes.FieldHandle] = ch.Handle
	for k, v := range extra {
		body[k] = v
	}
	return c.post(routes.Reauth, body)
}

func expectFresh(t *testing.T, w *world, c *client, before core.SessionAttrs) {
	t.Helper()
	a := c.attrs()
	if a.Lineage() != before.Lineage() || !a.PrimaryAt().Equal(w.clock.Now()) || !a.SecondAt().Equal(w.clock.Now()) {
		t.Fatalf("reauthentication must keep the lineage and refresh both timestamps: primary=%v second=%v", a.PrimaryAt(), a.SecondAt())
	}
}

// TestPasskeyUserReauthenticatesWithOneAssertion closes the DESIGN §5.3 gap: a passkey-enrolled
// subject is offered the passkey at /reauth and one assertion with user verification makes its
// session fresh, without spending a recovery code.
func TestPasskeyUserReauthenticatesWithOneAssertion(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	c := w.passkeySession("alice@example.com", "correct horse", a)
	before := c.attrs()
	w.clock.Advance(window + time.Minute)
	expectError(t, c.post(routes.MFATOTPEnroll, nil), http.StatusForbidden, "reauth_required")

	rec := c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"})
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateMFARequired || !slices.Equal(b.Factors, []string{"recovery_code", "passkey"}) {
		t.Fatalf("body %+v", b)
	}

	rec = c.finishPasskeyReauth(a, c.beginPasskeyReauth(), nil)
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateReauthenticated {
		t.Fatalf("body %+v", b)
	}
	expectFresh(t, w, c, before)
	if f := c.attrs().Factors(); !slices.Contains(f, core.FactorPasskey) || !slices.Contains(f, core.FactorUserVerification) {
		t.Fatalf("factors %v", f)
	}
	expect(t, c.post(routes.MFATOTPEnroll, nil), http.StatusOK)
}

func TestPasskeyReauthWithPasswordChecksIt(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	c := w.passkeySession("alice@example.com", "correct horse", a)
	before := c.attrs()
	w.clock.Advance(window + time.Minute)
	ch := c.beginPasskeyReauth()
	expectError(t, c.finishPasskeyReauth(a, ch, map[string]any{routes.FieldPassword: "wrong"}), http.StatusUnauthorized, "invalid_credentials")
	if after := c.attrs(); !after.SecondAt().Equal(before.SecondAt()) {
		t.Fatal("a refused password refreshed the session")
	}
	expect(t, c.finishPasskeyReauth(a, ch, map[string]any{routes.FieldPassword: "correct horse"}), http.StatusOK)
	expectFresh(t, w, c, before)
}

// TestPasskeyReauthNeedsNoPassword covers a deployment without the Password module (and so an
// account without a password): the passkey alone reauthenticates.
func TestPasskeyReauthNeedsNoPassword(t *testing.T) {
	w := newWorldWith(t, options{noPasswords: true})
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	c := w.passkeySession("alice@example.com", "correct horse", a)
	before := c.attrs()
	w.clock.Advance(window + time.Minute)
	expectError(t, c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"}), http.StatusBadRequest, "reauth_method_unavailable")
	expect(t, c.finishPasskeyReauth(a, c.beginPasskeyReauth(), nil), http.StatusOK)
	expectFresh(t, w, c, before)
}

// TestPasskeyReauthWithoutTheMFAModule asserts that a passkey-only subject is offered the passkey,
// not reported as missing a module, when only the Passkey module is enabled.
func TestPasskeyReauthWithoutTheMFAModule(t *testing.T) {
	w := newWorldWith(t, options{noMFAModule: true})
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	c := w.passkeySession("alice@example.com", "correct horse", a)
	w.clock.Advance(window + time.Minute)
	rec := c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"})
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); !slices.Equal(b.Factors, []string{"passkey"}) {
		t.Fatalf("body %+v", b)
	}
	if n := w.sink.count(event.MFAModuleMissing); n != 0 {
		t.Fatalf("MFAModuleMissing emitted %d times with the Passkey module enabled", n)
	}
	expect(t, c.finishPasskeyReauth(a, c.beginPasskeyReauth(), nil), http.StatusOK)
}

func TestPasskeyReauthIsBoundToItsSession(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	first := w.passkeySession("alice@example.com", "correct horse", a)
	second := w.passkeySession("alice@example.com", "correct horse", a)
	ch := first.beginPasskeyReauth()
	expectError(t, second.finishPasskeyReauth(a, ch, nil), http.StatusUnauthorized, "passkey_rejected")
	expectError(t, first.finishPasskeyReauth(a, ch, nil), http.StatusUnauthorized, "passkey_rejected")

	login := w.native()
	flowHandle := decode[journeyBody](t, login.login("alice@example.com", "correct horse", nil)).Flow
	rec := login.post(routes.MFAPasskeyBegin, map[string]any{routes.FieldFlow: flowHandle})
	expect(t, rec, http.StatusOK)
	expectError(t, first.finishPasskeyReauth(a, decode[passkeyChallenge](t, rec), nil), http.StatusUnauthorized, "passkey_rejected")

	ch = first.beginPasskeyReauth()
	body := map[string]any{}
	must(t, json.Unmarshal(a.Login(t, ch.Options), &body))
	body[routes.FieldHandle] = ch.Handle
	body[routes.FieldFlow] = flowHandle
	expect(t, login.post(routes.MFAPasskeyFinish, body), http.StatusUnauthorized)
	if w.sink.count(event.SessionIssued) != 0 {
		t.Fatal("a reauthentication ceremony completed a login")
	}
	expect(t, first.finishPasskeyReauth(a, first.beginPasskeyReauth(), nil), http.StatusOK)
}

func TestPasskeyReauthNeedsASession(t *testing.T) {
	w := newWorld(t)
	expectError(t, w.native().post(routes.Reauth, map[string]any{routes.FieldFactor: "passkey"}), http.StatusUnauthorized, "unauthenticated")
}

// TestRefusedPasskeyCompletionEmitsNoMFAVerified pins the event order of §5.1 step 3: MFAVerified
// is emitted only once the flow is consumed and the session issued.
func TestRefusedPasskeyCompletionEmitsNoMFAVerified(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com", "correct horse")
	a := w.enrollPasskey("alice@example.com", "correct horse")
	c := w.native()
	flowHandle := decode[journeyBody](t, c.login("alice@example.com", "correct horse", nil)).Flow
	rec := c.post(routes.MFAPasskeyBegin, map[string]any{routes.FieldFlow: flowHandle})
	expect(t, rec, http.StatusOK)
	ch := decode[passkeyChallenge](t, rec)
	_, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded})
	must(t, err)
	body := map[string]any{}
	must(t, json.Unmarshal(a.Login(t, ch.Options), &body))
	body[routes.FieldHandle] = ch.Handle
	body[routes.FieldFlow] = flowHandle
	expect(t, c.post(routes.MFAPasskeyFinish, body), http.StatusUnauthorized)
	if w.sink.count(event.SessionIssued) != 0 || w.sink.count(event.MFAVerified) != 0 {
		t.Fatalf("issued=%d verified=%d, want no event for a refused completion", w.sink.count(event.SessionIssued), w.sink.count(event.MFAVerified))
	}
}

func TestRefusedTOTPCompletionEmitsNoMFAVerified(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.native()
	flowHandle := decode[journeyBody](t, c.login("alice@example.com", "correct horse", nil)).Flow
	_, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded})
	must(t, err)
	fields := map[string]any{routes.FieldFlow: flowHandle, routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())}
	expect(t, c.post(routes.MFAChallenge, fields), http.StatusUnauthorized)
	if w.sink.count(event.SessionIssued) != 0 || w.sink.count(event.MFAVerified) != 0 {
		t.Fatalf("issued=%d verified=%d, want no event for a refused completion", w.sink.count(event.SessionIssued), w.sink.count(event.MFAVerified))
	}
}
