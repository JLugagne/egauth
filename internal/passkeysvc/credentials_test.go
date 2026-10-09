package passkeysvc_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/webauthntest"
)

func TestRegistrationTakesTheSessionSubjectAndReissues(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	before := w.sessions.attrsOf(tok)
	reg := w.register(tok, webauthntest.New(origin))
	if reg.State != "passkey_registered" || reg.SessionEnded || reg.Credential.Discoverable != "confirmed" {
		t.Fatalf("answer %+v", reg)
	}
	creds := w.credentials(sub)
	if len(creds) != 1 || creds[0].Subject != sub {
		t.Fatal("the credential is not the session subject's")
	}
	bumps := w.mutator.bumps()
	if len(bumps) != 1 || bumps[0].Change != identity.FactorPasskeyAdded || bumps[0].Keep != before.Lineage() {
		t.Fatalf("bumps %+v", bumps)
	}
	after := w.sessions.attrsOf(tok)
	if !after.HasFactor(core.FactorPasskeyStepUp) || after.Epoch() != w.epoch(sub) || !after.SecondAt().Equal(before.SecondAt()) {
		t.Fatal("the session was not reissued with pk_stepup enrolled and secondAt unchanged")
	}
	if w.sink.count(event.CredentialAdded) != 1 {
		t.Fatal("no CredentialAdded event")
	}
}

func TestRegistrationHandleIsBoundToItsSubject(t *testing.T) {
	w := newWorld(t)
	alice := w.user("alice@example.com")
	mallory := w.user("mallory@example.com")
	c := w.beginRegistration(w.session(alice))
	a := webauthntest.New(origin)
	rec := w.finishRegistration(w.session(mallory), c, a.Register(t, c.Options), nil)
	expect(t, rec, http.StatusBadRequest)
	if len(w.credentials(alice))+len(w.credentials(mallory)) != 0 {
		t.Fatal("a foreign registration handle stored a credential")
	}
}

func TestRegistrationDiesWithASecurityChange(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	c := w.beginRegistration(tok)
	body := webauthntest.New(origin).Register(t, c.Options)
	if _, err := w.identity.Apply(context.Background(), identity.BumpEpoch{Subject: sub, Keep: w.sessions.attrsOf(tok).Lineage(), Change: identity.FactorTOTPEnrolled}); err != nil {
		t.Fatal(err)
	}
	if err := w.sessions.replace(w.sessions.attrsOf(tok).Lineage(), reepoch(t, w, tok)); err != nil {
		t.Fatal(err)
	}
	expect(t, w.finishRegistration(tok, c, body, nil), http.StatusBadRequest)
	if len(w.credentials(sub)) != 0 {
		t.Fatal("a registration begun before a security change was stored")
	}
}

func reepoch(t *testing.T, w *world, tok string) core.SessionAttrs {
	t.Helper()
	a := w.sessions.attrsOf(tok)
	st, err := accounts{identity: w.identity, unverified: w.unverified}.AccountState(context.Background(), a.Subject())
	if err != nil {
		t.Fatal(err)
	}
	n, err := core.FactorEnrolled(a, core.FactorTOTP, st)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRegistrationRefusesAReplayedHandleAndDuplicates(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	a := webauthntest.New(origin)
	c := w.beginRegistration(tok)
	body := a.Register(t, c.Options)
	expect(t, w.finishRegistration(tok, c, body, map[string]any{routes.FieldNickname: "  Laptop "}), http.StatusOK)
	expect(t, w.finishRegistration(tok, c, body, nil), http.StatusBadRequest)
	if creds := w.credentials(sub); len(creds) != 1 || creds[0].Nickname != "Laptop" {
		t.Fatalf("credentials %+v", creds)
	}
	c = w.beginRegistration(tok)
	if _, err := a.Create(c.Options); !errors.Is(err, webauthntest.ErrInvalidState) {
		t.Fatalf("an excluded authenticator registered again: %v", err)
	}
}

func TestRegistrationNeedsUserVerification(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	tok := w.session(sub)
	a := webauthntest.New(origin)
	a.ClientUserVerification = "discouraged"
	c := w.beginRegistration(tok)
	expect(t, w.finishRegistration(tok, c, a.Register(t, c.Options), nil), http.StatusBadRequest)
	if len(w.credentials(sub)) != 0 {
		t.Fatal("a credential registered without UV was stored")
	}
}

func TestListAnswersTheDesignView(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	tok := w.session(sub)
	if err := w.passkeys.Suspend(context.Background(), sub, a.Credentials()[0].ID, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	rec := w.do(req{path: routes.PasskeyCredentials, token: tok, method: http.MethodGet})
	expect(t, rec, http.StatusOK)
	var raw struct {
		Credentials []map[string]any `json:"credentials"`
	}
	decodeInto(t, rec, &raw)
	if len(raw.Credentials) != 1 {
		t.Fatalf("listed %v", raw.Credentials)
	}
	got := raw.Credentials[0]
	want := []string{"credential_id", "nickname", "transports", "backup_eligible", "backup_state", "discoverable", "suspended", "needs_reregistration", "created_at", "last_used_at"}
	if len(got) != len(want) {
		t.Fatalf("keys %v", got)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing %s in %v", k, got)
		}
	}
	if got["credential_id"] != b64(a.Credentials()[0].ID) || got["suspended"] != true || got["needs_reregistration"] != false {
		t.Fatalf("view %v", got)
	}
	if strings.Contains(rec.Body.String(), "public") || strings.Contains(rec.Body.String(), sub.User.String()) {
		t.Fatal("the listing leaks key material or the subject")
	}
	legacy := passkeysvc.View(passkey.Credential{ID: []byte{1}, Discoverable: passkey.Legacy})
	if !legacy.NeedsReregistration || legacy.Discoverable != "legacy" {
		t.Fatalf("legacy view %+v", legacy)
	}
	for _, st := range []passkey.DiscoverableState{passkey.Confirmed, passkey.Inferred} {
		if passkeysvc.View(passkey.Credential{ID: []byte{1}, Discoverable: st}).NeedsReregistration {
			t.Fatalf("%v needs re-registration", st)
		}
	}
}

func TestRenameRefusals(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	_, mallory := w.enrolled("mallory@example.com")
	tok := w.session(sub)
	id := b64(a.Credentials()[0].ID)
	cases := []struct {
		fields map[string]any
		status int
		code   string
	}{
		{map[string]any{routes.FieldCredentialID: "a+b/", routes.FieldNickname: "x"}, http.StatusBadRequest, "invalid_credential_id"},
		{map[string]any{routes.FieldCredentialID: id + "==", routes.FieldNickname: "x"}, http.StatusBadRequest, "invalid_credential_id"},
		{map[string]any{routes.FieldCredentialID: b64(mallory.Credentials()[0].ID), routes.FieldNickname: "x"}, http.StatusNotFound, "credential_not_found"},
		{map[string]any{routes.FieldCredentialID: id, routes.FieldNickname: "  "}, http.StatusBadRequest, "invalid_nickname"},
		{map[string]any{routes.FieldCredentialID: id, routes.FieldNickname: strings.Repeat("é", passkeysvc.MaxNicknameRunes+1)}, http.StatusBadRequest, "invalid_nickname"},
		{map[string]any{routes.FieldCredentialID: id, routes.FieldNickname: "bad‮name"}, http.StatusBadRequest, "invalid_nickname"},
	}
	for i, c := range cases {
		rec := w.do(req{path: routes.PasskeyCredentialsRename, token: tok, fields: c.fields})
		if rec.Code != c.status || errorCode(t, rec) != c.code {
			t.Errorf("case %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if w.credentials(sub)[0].Discoverable != passkey.Confirmed {
		t.Fatal("rename changed the discoverable state")
	}
}

func TestDeleteBumpsTheEpochAndPrunesRecoveryCodes(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	second := webauthntest.New(origin)
	w.register(w.session(sub), second)
	ctx := context.Background()
	if err := w.mfa.ReplaceRecoveryCodes(ctx, sub, recoveryHashes(t)); err != nil {
		t.Fatal(err)
	}
	used := 0
	remaining := func() bool {
		t.Helper()
		err := w.mfa.ConsumeRecoveryCode(ctx, sub, recoveryHashes(t)[used])
		used++
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	del := func(id []byte) {
		t.Helper()
		tok := w.session(sub)
		rec := w.do(req{path: routes.PasskeyCredentialsDelete, token: tok, fields: map[string]any{routes.FieldCredentialID: b64(id)}})
		expect(t, rec, http.StatusOK)
		var out struct {
			SessionEnded bool `json:"session_ended"`
		}
		decodeInto(t, rec, &out)
		if !out.SessionEnded || w.sessions.attrsOf(tok).Epoch() == w.epoch(sub) {
			t.Fatal("delete did not end the current session")
		}
	}
	bumps := len(w.mutator.bumps())
	del(a.Credentials()[0].ID)
	b := w.mutator.bumps()
	if len(b) != bumps+1 || b[len(b)-1].Change != identity.FactorPasskeyRemoved || b[len(b)-1].Keep != uuid.Nil {
		t.Fatalf("bumps %+v", b)
	}
	if !remaining() {
		t.Fatal("recovery codes were removed while an active passkey remains")
	}
	del(second.Credentials()[0].ID)
	if remaining() {
		t.Fatal("recovery codes survived the last second factor")
	}
	if len(w.credentials(sub)) != 0 || w.sink.count(event.CredentialRemoved) != 2 {
		t.Fatal("credentials or events left")
	}
	rec := w.do(req{path: routes.PasskeyCredentialsDelete, token: w.session(sub), fields: map[string]any{routes.FieldCredentialID: b64(a.Credentials()[0].ID)}})
	expect(t, rec, http.StatusNotFound)
}

func TestDeleteKeepsRecoveryCodesWhileTOTPRemains(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	ctx := context.Background()
	now := w.clock.Now()
	if err := w.mfa.SaveTOTP(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte("sealed"), AADVersion: mfa.AADVersionCurrent, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := w.mfa.ConfirmEnrollment(ctx, mfa.Enrollment{Subject: sub, Sealed: []byte("sealed"), AADVersion: mfa.AADVersionCurrent, CreatedAt: now, ConfirmedAt: &now}, recoveryHashes(t)); err != nil {
		t.Fatal(err)
	}
	rec := w.do(req{path: routes.PasskeyCredentialsDelete, token: w.session(sub), fields: map[string]any{routes.FieldCredentialID: b64(a.Credentials()[0].ID)}})
	expect(t, rec, http.StatusOK)
	if err := w.mfa.ConsumeRecoveryCode(ctx, sub, recoveryHashes(t)[0]); err != nil {
		t.Fatalf("recovery codes were removed while TOTP remains: %v", err)
	}
}

func recoveryHashes(t *testing.T) []string {
	t.Helper()
	out := make([]string, 0, 3)
	for i := range 3 {
		out = append(out, fmt.Sprintf("hash-%02d-%s", i, strings.Repeat("x", 24)))
	}
	return out
}

func TestManagementNeedsASession(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{routes.PasskeyRegisterBegin, routes.PasskeyRegisterFinish, routes.PasskeyCredentialsRename, routes.PasskeyCredentialsDelete} {
		if rec := w.do(req{path: p, bearer: true}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := w.do(req{path: routes.PasskeyCredentials, bearer: true, method: http.MethodGet}); rec.Code != http.StatusUnauthorized {
		t.Errorf("list: %d", rec.Code)
	}
}

func TestNewReportsEveryMissingMember(t *testing.T) {
	_, err := passkeysvc.New(passkeysvc.Config{})
	if !errors.Is(err, passkeysvc.ErrInvalidConfig) {
		t.Fatalf("New(zero) = %v", err)
	}
	for _, m := range []string{"Passkeys", "MFA", "Identity", "Accounts", "Mutations", "Ceremonies", "Origins", "Cookies", "DisplayName", "Audit", "DataKey"} {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("missing %s not reported: %v", m, err)
		}
	}
	w := newWorld(t)
	trusted, err := csrf.NewOrigins(origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := w.config(trusted)
	cfg.DataKey = make([]byte, 32)
	if _, err := passkeysvc.New(cfg); !errors.Is(err, passkeysvc.ErrInvalidConfig) {
		t.Fatalf("weak data key accepted: %v", err)
	}
	if _, err := w.svc.Endpoints(nil); !errors.Is(err, passkeysvc.ErrNilIssuer) {
		t.Fatalf("nil issuer: %v", err)
	}
	cfg = w.config(trusted)
	if s := fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg); leaks(s, testDataKey()) {
		t.Fatal("the config prints the data key")
	}
}
