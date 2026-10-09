package flow_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/routes"
)

func (w *world) mfaSession(email, password string, e totpEnrollment) *client {
	w.t.Helper()
	c := w.native()
	rec := c.login(email, password, nil)
	expect(w.t, rec, http.StatusOK)
	flowHandle := decode[journeyBody](w.t, rec).Flow
	rec = c.post(routes.MFAChallenge, map[string]any{routes.FieldFlow: flowHandle, routes.FieldFactor: "totp", routes.FieldCode: totpAt(w.t, e.secret, w.clock.Now())})
	expect(w.t, rec, http.StatusOK)
	w.clock.Advance(30 * time.Second)
	return c
}

// TestPasswordAloneNeverRefreshesSecondAt closes C-44: a phished password plus a stolen session
// cannot pass the sensitive gate of a multi-factor subject.
func TestPasswordAloneNeverRefreshesSecondAt(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.mfaSession("alice@example.com", "correct horse", e)
	before := c.attrs()
	w.clock.Advance(window + time.Minute)
	expectError(t, c.post(routes.MFATOTPEnroll, nil), http.StatusForbidden, "reauth_required")

	rec := c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"})
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateMFARequired || !slices.Equal(b.Factors, []string{"totp", "recovery_code"}) {
		t.Fatalf("body %+v", b)
	}
	after := c.attrs()
	if !after.PrimaryAt().Equal(before.PrimaryAt()) || !after.SecondAt().Equal(before.SecondAt()) {
		t.Fatal("a password-only reauthentication changed the session's freshness")
	}
	expectError(t, c.post(routes.MFATOTPEnroll, nil), http.StatusForbidden, "reauth_required")

	rec = c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse", routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())})
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateReauthenticated {
		t.Fatalf("body %+v", b)
	}
	fresh := c.attrs()
	if fresh.Lineage() != before.Lineage() || !fresh.SecondAt().Equal(w.clock.Now()) || !fresh.PrimaryAt().Equal(w.clock.Now()) {
		t.Fatal("reauthentication must keep the lineage and refresh both timestamps")
	}
	expectError(t, c.post(routes.MFATOTPEnroll, nil), http.StatusConflict, "totp_already_enrolled")
}

func TestReauthWithoutEnrollmentRefreshesThePrimary(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	c := w.native()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	before := c.attrs()
	w.clock.Advance(window + time.Minute)
	expectError(t, c.post(routes.MFATOTPEnroll, nil), http.StatusForbidden, "reauth_required")
	rec := c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"})
	expect(t, rec, http.StatusOK)
	a := c.attrs()
	if a.Lineage() != before.Lineage() || !a.PrimaryAt().Equal(w.clock.Now()) || !a.SecondAt().IsZero() || !slices.Equal(a.Factors(), []core.Factor{core.FactorPassword}) {
		t.Fatal("password reauthentication must refresh only primaryAt")
	}
	expect(t, c.post(routes.MFATOTPEnroll, nil), http.StatusOK)
}

func TestReauthChecksThePasswordBeforeAnySecondFactor(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.mfaSession("alice@example.com", "correct horse", e)
	expectError(t, c.post(routes.Reauth, map[string]any{routes.FieldPassword: "wrong", routes.FieldFactor: "recovery_code", routes.FieldCode: e.codes[0]}),
		http.StatusUnauthorized, "invalid_credentials")
	expect(t, c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse", routes.FieldFactor: "recovery_code", routes.FieldCode: e.codes[0]}), http.StatusOK)
	expectError(t, c.post(routes.Reauth, map[string]any{}), http.StatusBadRequest, "invalid_request")
	expectError(t, c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse", routes.FieldFactor: "sms"}), http.StatusBadRequest, "invalid_factor")
	expectError(t, c.post(routes.Reauth, map[string]any{routes.FieldFactor: "passkey"}), http.StatusConflict, "no_passkey")
	expect(t, w.native().post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"}), http.StatusUnauthorized)
}

func TestReauthNeedsThePasswordModule(t *testing.T) {
	w := newWorldWith(t, options{noPasswords: true})
	w.user("alice@example.com", "correct horse")
	c := w.native()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	expectError(t, c.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse"}), http.StatusBadRequest, "reauth_method_unavailable")
}

// TestFactorEnrollmentReissuesTheResumedSession closes T-09, I-05, I-08 and C-45: the session that
// enrolled is reissued from the artefact the preamble resumed, keeps its lineage, gains the factor
// with secondAt unchanged, and other sessions of the subject die.
func TestFactorEnrollmentReissuesTheResumedSession(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	other := w.native()
	expect(t, other.login("alice@example.com", "correct horse", nil), http.StatusOK)
	c := w.native()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	before := c.attrs()
	rec := c.post(routes.MFATOTPEnroll, nil)
	expect(t, rec, http.StatusOK)
	secret := decode[struct {
		Secret string `json:"secret"`
	}](t, rec).Secret
	expect(t, c.post(routes.MFATOTPConfirm, map[string]any{routes.FieldCode: totpAt(t, secret, w.clock.Now())}), http.StatusOK)
	a := c.attrs()
	if a.Lineage() != before.Lineage() || !slices.Equal(a.Factors(), []core.Factor{core.FactorPassword, core.FactorTOTP}) || !a.SecondAt().IsZero() || a.Epoch() != before.Epoch()+1 {
		t.Fatalf("reissued session factors=%v secondAt=%v epoch=%d", a.Factors(), a.SecondAt(), a.Epoch())
	}
	expect(t, other.get(routes.Session), http.StatusUnauthorized)
	expectError(t, c.post(routes.MFARecoveryCodesRegenerate, nil), http.StatusForbidden, "reauth_required")
}

func TestPasswordChangeReissue(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	c := w.browser()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	before := c.attrs()
	w.clock.Advance(time.Minute)
	expect(t, c.post(routes.PasswordChange, map[string]any{routes.FieldConfirm: "bump"}), http.StatusOK)
	a := c.attrs()
	if a.Lineage() != before.Lineage() || !a.PrimaryAt().Equal(w.clock.Now()) || a.Epoch() != before.Epoch()+1 || a.MustChangePassword() {
		t.Fatal("PasswordChanged must keep the lineage, refresh primaryAt and stamp the new epoch")
	}
	expectError(t, c.post(routes.PasswordChange, map[string]any{routes.FieldConfirm: "zero"}), http.StatusInternalServerError, "internal_error")
	rec := c.post(routes.PasswordChange, nil)
	expect(t, rec, http.StatusUnauthorized)
	if _, ok := c.cookie(cookie.StatefulSession); ok {
		t.Fatal("a failed reissue must clear the session cookie")
	}
}

// TestDisablingTheLastFactorDropsTheRequirement asserts the invariant behind the "TOTP disabled while
// recovery codes remain" row of TestEnrolledGolden: removing the last second factor removes the
// recovery codes, so the next login is admitted on the password and an old code is refused.
func TestDisablingTheLastFactorDropsTheRequirement(t *testing.T) {
	w := newWorld(t)
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.mfaSession("alice@example.com", "correct horse", e)
	expect(t, c.post(routes.MFATOTPDisable, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())}), http.StatusOK)
	n := w.native()
	rec := n.login("alice@example.com", "correct horse", nil)
	expect(t, rec, http.StatusOK)
	if b := decode[journeyBody](t, rec); b.State != issuance.StateAuthenticated {
		t.Fatalf("body %+v", b)
	}
	expectError(t, n.post(routes.Reauth, map[string]any{routes.FieldPassword: "correct horse", routes.FieldFactor: "recovery_code", routes.FieldCode: e.codes[1]}),
		http.StatusUnauthorized, "invalid_code")
}

func TestReauthPageRedirectsBrowsers(t *testing.T) {
	w := newWorldWith(t, options{pages: issuance.Pages{Reauth: "/confirm-identity"}})
	w.user("alice@example.com", "correct horse")
	e := w.enrollTOTP("alice@example.com", "correct horse")
	c := w.browser()
	expect(t, c.login("alice@example.com", "correct horse", nil), http.StatusOK)
	expect(t, c.post(routes.MFAChallenge, map[string]any{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, e.secret, w.clock.Now())}), http.StatusOK)
	w.clock.Advance(window + time.Minute)
	rec := c.form(routes.Reauth, url.Values{routes.FieldPassword: {"correct horse"}})
	expect(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != "/confirm-identity" {
		t.Fatalf("Location %q", loc)
	}
}
