package mfasvc_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/mfasvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
)

func TestEnrollReturnsAProvisioningURIAndStoresAnUnconfirmedSecret(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	b := w.enroll(w.session(sub))
	if b.State != "totp_enrollment_started" || len(b.Secret) != 32 {
		t.Fatalf("enroll body = %+v", b)
	}
	u, err := url.Parse(b.URI)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != b.Secret || u.Query().Get("issuer") != "Example" {
		t.Fatalf("uri = %q", b.URI)
	}
	if !strings.Contains(u.Path, "ann@example.com") {
		t.Fatalf("uri label = %q", u.Path)
	}
	ok, err := w.mfa.HasConfirmedTOTP(context.Background(), sub)
	if err != nil || ok {
		t.Fatalf("confirmed after enroll = %v, %v", ok, err)
	}
	if got := w.mutator.changes(); len(got) != 0 {
		t.Fatalf("enroll bumped the epoch: %v", got)
	}
}

func TestEnrollRefusesAConfirmedTOTP(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	tok := w.session(sub, core.FactorPassword, core.FactorTOTP)
	rec := w.post(tok, routes.MFATOTPEnroll, nil)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "totp_already_enrolled" {
		t.Fatalf("re-enroll = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := w.svc.Verify(context.Background(), sub, core.FactorTOTP, totpAt(t, secret, w.clock.Now())); err != nil {
		t.Fatalf("the confirmed secret no longer verifies: %v", err)
	}
}

func TestReEnrollKeepsTheLockoutCounter(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	b := w.enroll(tok)
	wrong := wrongCode(totpAt(t, b.Secret, w.clock.Now()))
	for range mfasvc.MaxAttempts {
		w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: wrong})
	}
	b = w.enroll(tok)
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(t, b.Secret, w.clock.Now())})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("confirm after re-enroll while locked = %d %s", rec.Code, rec.Body.String())
	}
}

func TestConfirmBumpsTheEpochBeforeConfirmingAndReissues(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	other := w.session(sub)
	before := w.epoch(sub)
	b := w.enroll(tok)
	w.mutator.before = func(m identity.Mutation) {
		if ok, _ := w.mfa.HasConfirmedTOTP(ctx, sub); ok {
			t.Error("TOTP confirmed before the epoch bump (§7.1 order)")
		}
	}
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(t, b.Secret, w.clock.Now())})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	var c codesBody
	decodeInto(t, rec, &c)
	if c.State != "totp_enabled" || len(c.RecoveryCodes) != mfasvc.RecoveryCodeCount || c.SessionEnded {
		t.Fatalf("confirm body = %+v", c)
	}
	if got := w.mutator.changes(); !slices.Equal(got, []identity.FactorChange{identity.FactorTOTPEnrolled}) {
		t.Fatalf("epoch changes = %v", got)
	}
	if w.epoch(sub) != before+1 {
		t.Fatalf("epoch = %d; want %d", w.epoch(sub), before+1)
	}
	if ok, _ := w.mfa.HasConfirmedTOTP(ctx, sub); !ok {
		t.Fatal("TOTP not confirmed")
	}
	rs := w.issuer.all()
	if len(rs) != 1 || rs[0].change != core.FactorTOTP || rs[0].err != nil {
		t.Fatalf("reissues = %+v", rs)
	}
	a := w.sessions.attrsOf(tok)
	if !a.HasFactor(core.FactorTOTP) || !a.SecondAt().IsZero() || a.Epoch() != before+1 {
		t.Fatalf("reissued attrs: factors %v secondAt %v epoch %d", a.Factors(), a.SecondAt(), a.Epoch())
	}
	if rec := w.post(other, routes.MFARecoveryCodesRegenerate, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another session after confirm = %d; want 401", rec.Code)
	}
	if rec := w.post(tok, routes.MFARecoveryCodesRegenerate, nil); rec.Code != http.StatusForbidden || errorCode(t, rec) != "reauth_required" {
		t.Fatalf("enrolling session on a sensitive endpoint = %d %s; want reauth_required (C-45)", rec.Code, rec.Body.String())
	}
	if _, ok := w.sink.last(event.CredentialAdded); !ok {
		t.Fatal("no CredentialAdded event")
	}
}

func TestConfirmWithAWrongCodeChangesNothing(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	b := w.enroll(tok)
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: wrongCode(totpAt(t, b.Secret, w.clock.Now()))})
	if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != "invalid_code" {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if len(w.mutator.changes()) != 0 || len(w.issuer.all()) != 0 {
		t.Fatal("a failed confirm bumped or reissued")
	}
}

func TestConfirmWithoutPendingEnrollment(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	rec := w.post(w.session(sub), routes.MFATOTPConfirm, map[string]string{routes.FieldCode: "123456"})
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "totp_not_pending" {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
}

func TestConfirmSurvivesAFailedReissueWithTheCodes(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	b := w.enroll(tok)
	w.mutator.before = func(identity.Mutation) {
		_, _ = w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded})
	}
	rec := w.post(tok, routes.MFATOTPConfirm, map[string]string{routes.FieldCode: totpAt(t, b.Secret, w.clock.Now())})
	var c codesBody
	decodeInto(t, rec, &c)
	if rec.Code != http.StatusOK || !c.SessionEnded || len(c.RecoveryCodes) != mfasvc.RecoveryCodeCount {
		t.Fatalf("confirm with a racing epoch bump = %d %+v", rec.Code, c)
	}
}

func TestDisableNeedsAnExplicitFactorAndAValidCode(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	tok := w.session(sub, core.FactorPassword, core.FactorTOTP)
	rec := w.post(tok, routes.MFATOTPDisable, map[string]string{routes.FieldCode: totpAt(t, secret, w.clock.Now())})
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_factor" {
		t.Fatalf("disable without factor = %d %s", rec.Code, rec.Body.String())
	}
	rec = w.post(tok, routes.MFATOTPDisable, map[string]string{routes.FieldFactor: "totp", routes.FieldCode: wrongCode(totpAt(t, secret, w.clock.Now()))})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong code = %d %s", rec.Code, rec.Body.String())
	}
	if ok, _ := w.mfa.HasConfirmedTOTP(context.Background(), sub); !ok {
		t.Fatal("a failed disable removed TOTP")
	}
}

func TestDisableRemovesTOTPAndOrphanRecoveryCodes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	secret, codes := w.enrolled(sub)
	tok := w.session(sub, core.FactorPassword, core.FactorTOTP)
	before := w.epoch(sub)
	rec := w.post(tok, routes.MFATOTPDisable, map[string]string{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, secret, w.clock.Now())})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body.String())
	}
	var c codesBody
	decodeInto(t, rec, &c)
	if c.State != "totp_disabled" || !c.SessionEnded {
		t.Fatalf("disable body = %+v", c)
	}
	if _, err := w.mfa.GetTOTP(ctx, sub); err == nil {
		t.Fatal("TOTP still stored")
	}
	if w.epoch(sub) != before+1 || !slices.Contains(w.mutator.changes(), identity.FactorTOTPRemoved) {
		t.Fatalf("epoch %d changes %v", w.epoch(sub), w.mutator.changes())
	}
	if n, _ := w.mfa.CountEnrolled(ctx); n != 0 {
		t.Fatalf("recovery codes survive the last second factor: %d enrolled (D1)", n)
	}
	w.addPasskey(sub)
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[2]); err == nil {
		t.Fatal("a recovery code of the removed TOTP still verifies")
	}
	if _, ok := w.sink.last(event.CredentialRemoved); !ok {
		t.Fatal("no CredentialRemoved event")
	}
	if rec := w.post(tok, routes.MFATOTPEnroll, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after disable = %d; want 401", rec.Code)
	}
}

func TestDisableKeepsRecoveryCodesWhileAPasskeyRemains(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	_, codes := w.enrolled(sub)
	w.addPasskey(sub)
	tok := w.session(sub, core.FactorPasskey, core.FactorUserVerification)
	rec := w.post(tok, routes.MFATOTPDisable, map[string]string{routes.FieldFactor: "recovery_code", routes.FieldCode: codes[0]})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, codes[1]); err != nil {
		t.Fatalf("recovery code with a passkey left: %v", err)
	}
}

func TestDisableSharesTheTOTPLockout(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	secret, _ := w.enrolled(sub)
	wrong := wrongCode(totpAt(t, secret, w.clock.Now()))
	for range mfasvc.MaxAttempts {
		_, _ = w.svc.Verify(context.Background(), sub, core.FactorTOTP, wrong)
	}
	tok := w.session(sub, core.FactorPassword, core.FactorTOTP)
	rec := w.post(tok, routes.MFATOTPDisable, map[string]string{routes.FieldFactor: "totp", routes.FieldCode: totpAt(t, secret, w.clock.Now())})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("disable while locked = %d %s (C-40)", rec.Code, rec.Body.String())
	}
}

func TestRegenerateReplacesCodesAndNeedsASecondFactor(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := w.user("ann@example.com")
	rec := w.post(w.session(sub), routes.MFARecoveryCodesRegenerate, nil)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "no_second_factor" {
		t.Fatalf("regenerate without a factor = %d %s", rec.Code, rec.Body.String())
	}
	_, old := w.enrolled(sub)
	tok := w.session(sub, core.FactorPassword, core.FactorTOTP)
	before := w.epoch(sub)
	rec = w.post(tok, routes.MFARecoveryCodesRegenerate, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("regenerate = %d %s", rec.Code, rec.Body.String())
	}
	var c codesBody
	decodeInto(t, rec, &c)
	if c.State != "recovery_codes_regenerated" || len(c.RecoveryCodes) != mfasvc.RecoveryCodeCount || !c.SessionEnded {
		t.Fatalf("regenerate body = %+v", c)
	}
	if w.epoch(sub) != before+1 || !slices.Contains(w.mutator.changes(), identity.FactorRecoveryCodesRegenerated) {
		t.Fatal("regenerate did not bump the epoch with FactorRecoveryCodesRegenerated")
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, old[0]); err == nil {
		t.Fatal("an old recovery code still verifies")
	}
	if _, err := w.svc.Verify(ctx, sub, core.FactorRecoveryCode, c.RecoveryCodes[0]); err != nil {
		t.Fatalf("a new recovery code: %v", err)
	}
}

func TestRecoveryCodesAreDistinctAndWellFormed(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	_, codes := w.enrolled(sub)
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 || seen[c] {
			t.Fatalf("recovery code %q", c)
		}
		seen[c] = true
	}
}

func TestEndpointsNeedASession(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{routes.MFATOTPEnroll, routes.MFATOTPConfirm, routes.MFATOTPDisable, routes.MFARecoveryCodesRegenerate} {
		if rec := w.post("", p, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s anonymous = %d", p, rec.Code)
		}
	}
}

func TestStaleSessionCannotEnroll(t *testing.T) {
	w := newWorld(t)
	sub := w.user("ann@example.com")
	tok := w.session(sub)
	w.clock.Advance(11 * time.Minute)
	if rec := w.post(tok, routes.MFATOTPEnroll, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stale session enroll = %d", rec.Code)
	}
	if _, err := w.mfa.GetTOTP(context.Background(), sub); err == nil {
		t.Fatal("enrollment stored for a stale session")
	}
}

func TestNewReportsEveryMissingMember(t *testing.T) {
	_, err := mfasvc.New(mfasvc.Config{})
	if err == nil {
		t.Fatal("zero config accepted")
	}
	for _, name := range []string{"MFA", "Passkeys", "Identity", "Mutations", "KEK", "TOTPIssuer", "Audit"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error %q does not name %s", err, name)
		}
	}
	var nilStore *typedNil
	_, err = mfasvc.New(mfasvc.Config{MFA: nilStore})
	if err == nil || !strings.Contains(err.Error(), "MFA") {
		t.Fatalf("typed nil MFA accepted: %v", err)
	}
}

type typedNil struct{ mfa.Store }

func TestConfigRedactsTheKEK(t *testing.T) {
	c := mfasvc.Config{TOTPIssuer: "Example", KEK: newKEK(t)}
	for _, s := range []string{c.String(), c.GoString(), c.LogValue().String()} {
		if !strings.Contains(s, "REDACTED") || strings.Contains(s, "kek.Local") {
			t.Fatalf("config rendering %q", s)
		}
	}
}
