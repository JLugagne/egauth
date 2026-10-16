package passkeysvc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/webauthntest"
)

func (w *world) lastCompletion() completion {
	w.t.Helper()
	all := w.issuer.completions()
	if len(all) == 0 {
		w.t.Fatal("Issuer.Complete was never called")
	}
	return all[len(all)-1]
}

func TestDiscoverableLoginYieldsPasskeyAndUV(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	puts := w.ceremonies.puts.Load()
	c, cookies := w.beginLogin(nil)
	if w.ceremonies.puts.Load() != puts {
		t.Fatal("a discoverable begin wrote a ceremony row")
	}
	rec := w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options))
	expect(t, rec, http.StatusOK)
	done := w.lastCompletion()
	if done.err != nil {
		t.Fatal(done.err)
	}
	if done.pending.Bound() {
		t.Fatal("a discoverable begin bound a subject")
	}
	v := done.verified
	if v.Subject() != sub || !slices.Equal(v.Factors(), []core.Factor{core.FactorPasskey, core.FactorUserVerification}) || !v.Identifies() {
		t.Fatalf("verified %v %v", v.Subject(), v.Factors())
	}
	if !bytes.Equal(v.CredentialID(), a.Credentials()[0].ID) {
		t.Fatal("verified credential is not the one used")
	}
	if got, _ := done.added.Subject(); got != sub || !done.added.MultiFactor() {
		t.Fatal("Add did not bind the credential owner")
	}
	creds := w.credentials(sub)
	if creds[0].SignCount != 1 || creds[0].LastUsedAt == nil {
		t.Fatalf("counter %d last use %v", creds[0].SignCount, creds[0].LastUsedAt)
	}
}

func TestLoginBeginSealsRememberAndReturnTo(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	c, cookies := w.beginLogin(map[string]any{routes.FieldRemember: true, routes.FieldReturnTo: "/billing"})
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
	p := w.lastCompletion().pending
	if !p.RememberMe() || p.ReturnTo() != "/billing" || p.Transport() != core.TransportCookies {
		t.Fatalf("pending remember=%v return_to=%q transport=%v", p.RememberMe(), p.ReturnTo(), p.Transport())
	}
	c, cookies = w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
	if w.lastCompletion().pending.RememberMe() {
		t.Fatal("remember leaked into a later journey")
	}
}

func TestUsernameFirstBindsTheSubjectAtBegin(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	puts := w.ceremonies.puts.Load()
	c, cookies := w.beginLogin(map[string]any{routes.FieldIdentifier: "Alice@Example.com"})
	if w.ceremonies.puts.Load() != puts {
		t.Fatal("a username-first begin wrote a ceremony row")
	}
	allow := allowed(t, c.Options)
	if len(allow) != 1 || allow[0] != b64(a.Credentials()[0].ID) {
		t.Fatalf("allowCredentials %v", allow)
	}
	expect(t, w.finishLogin(c, cookies, a.Login(t, c.Options)), http.StatusOK)
	done := w.lastCompletion()
	if bound, ok := done.pending.Subject(); !ok || bound != sub {
		t.Fatal("the username-first Pending was not bound to the subject at begin")
	}
	if done.pending.EpochAtBind() != w.epoch(sub) {
		t.Fatal("the bind did not record the epoch")
	}
}

func TestUsernameFirstVictimBindWithAttackerCredentialIsRefused(t *testing.T) {
	w := newWorld(t)
	w.enrolled("victim@example.com")
	attacker, mallory := w.enrolled("mallory@example.com")
	c, cookies := w.beginLogin(map[string]any{routes.FieldIdentifier: "victim@example.com"})
	pk := publicKeyOf(t, c.Options)
	delete(pk, "allowCredentials")
	opts, err := json.Marshal(map[string]any{"publicKey": pk})
	if err != nil {
		t.Fatal(err)
	}
	rec := w.finishLogin(c, cookies, mallory.DiscoverableLogin(t, opts))
	expect(t, rec, http.StatusUnauthorized)
	if code := errorCode(t, rec); code != "passkey_rejected" {
		t.Fatalf("error %q", code)
	}
	if len(w.issuer.completions()) != 0 {
		t.Fatal("a foreign credential reached Complete")
	}
	if creds := w.credentials(attacker); creds[0].SignCount != 0 {
		t.Fatal("the refused assertion still advanced the attacker's counter")
	}
}

func TestForeignOwnerIsRefusedByAdd(t *testing.T) {
	w := newWorld(t)
	victim, _ := w.enrolled("victim@example.com")
	_, mallory := w.enrolled("mallory@example.com")
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, mallory.DiscoverableLogin(t, c.Options)), http.StatusOK)
	v := w.lastCompletion().verified
	st, err := accounts{identity: w.identity, unverified: w.unverified}.AccountState(context.Background(), victim)
	if err != nil {
		t.Fatal(err)
	}
	p, err := core.NewPending(core.TenantID{}, core.RememberDeclined, redirect.Target{}, core.TransportCookies, core.RememberUserChoice, w.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p, err = p.Bind(victim, st); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(v, st); err != core.ErrSubjectMismatch {
		t.Fatalf("Add of a foreign owner's pk = %v, want ErrSubjectMismatch", err)
	}
}

func TestUnknownIdentifierGetsDeterministicFakeOptions(t *testing.T) {
	w := newWorld(t)
	w.enrolled("alice@example.com")
	w.user("nopasskey@example.com")
	ids := func(identifier string) []string {
		c, _ := w.beginLogin(map[string]any{routes.FieldIdentifier: identifier})
		if c.Handle == "" || len(c.Options) == 0 {
			t.Fatalf("no challenge for %s", identifier)
		}
		return allowed(t, c.Options)
	}
	puts := w.ceremonies.puts.Load()
	ghost := ids("ghost@example.com")
	if len(ghost) == 0 || !slices.Equal(ghost, ids("ghost@example.com")) || !slices.Equal(ghost, ids("Ghost@Example.com")) {
		t.Fatalf("fake ids are not deterministic: %v", ghost)
	}
	if slices.Equal(ghost, ids("other@example.com")) {
		t.Fatal("two identifiers share fake ids")
	}
	if len(ids("nopasskey@example.com")) == 0 {
		t.Fatal("an account without passkeys answered an empty allow list")
	}
	if w.ceremonies.puts.Load() != puts {
		t.Fatal("username-first begins wrote ceremony rows")
	}
	c, cookies := w.beginLogin(map[string]any{routes.FieldIdentifier: "ghost@example.com"})
	stray := webauthntest.New(origin)
	if _, err := stray.Get(c.Options); err == nil {
		t.Fatal("a fake credential id matched an authenticator")
	}
	pk := publicKeyOf(t, c.Options)
	delete(pk, "allowCredentials")
	opts, err := json.Marshal(map[string]any{"publicKey": pk})
	if err != nil {
		t.Fatal(err)
	}
	_, alice := w.enrolled("alice2@example.com")
	expect(t, w.finishLogin(c, cookies, alice.DiscoverableLogin(t, opts)), http.StatusUnauthorized)
}

func TestReplayedHandleIsRefused(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
	rec := w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options))
	expect(t, rec, http.StatusUnauthorized)
	if w.sink.count(event.LoginFailed) == 0 {
		t.Fatal("no LoginFailed event")
	}
}

func TestLoginFinishRequiresTheBindSecret(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	c, _ := w.beginLogin(nil)
	rec := w.finishLogin(c, nil, a.DiscoverableLogin(t, c.Options))
	expect(t, rec, http.StatusBadRequest)
	if code := errorCode(t, rec); code != "unbound_ceremony" {
		t.Fatalf("error %q", code)
	}
	rec = w.do(req{path: routes.PasskeyLoginBegin, bearer: true})
	expect(t, rec, http.StatusOK)
	var bc challenge
	decodeInto(t, rec, &bc)
	if bc.Bind == "" {
		t.Fatal("a bearer begin answered no bind")
	}
	body := a.DiscoverableLogin(t, bc.Options)
	rec = w.do(req{path: routes.PasskeyLoginFinish, bearer: true, body: body, fields: map[string]any{routes.FieldHandle: bc.Handle}})
	expect(t, rec, http.StatusBadRequest)
	rec = w.do(req{path: routes.PasskeyLoginFinish, bearer: true, body: body, fields: map[string]any{routes.FieldHandle: bc.Handle, routes.FieldBind: bc.Bind}})
	expect(t, rec, http.StatusOK)
}

func TestAssertionWithoutUserVerificationIsRefused(t *testing.T) {
	w := newWorld(t)
	_, a := w.enrolled("alice@example.com")
	a.ClientUserVerification = "discouraged"
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusUnauthorized)
	if len(w.issuer.completions()) != 0 {
		t.Fatal("an assertion without UV reached Complete")
	}
}

func TestSuspendedCredentialIsRefused(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	if err := w.passkeys.Suspend(context.Background(), sub, a.Credentials()[0].ID, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusUnauthorized)
	c, _ = w.beginLogin(map[string]any{routes.FieldIdentifier: "alice@example.com"})
	if _, err := a.Get(c.Options); err == nil {
		t.Fatal("a suspended credential was offered in the allow list")
	}
}

func TestClonedAuthenticatorSuspendsTheCredential(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	clone := a.Clone()
	c, cookies := w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
	c, cookies = w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, clone.DiscoverableLogin(t, c.Options)), http.StatusUnauthorized)
	creds := w.credentials(sub)
	if len(creds) != 1 || creds[0].Active() {
		t.Fatal("the clone signal did not suspend, or deleted, the credential")
	}
	if w.sink.count(event.AccountBlocked) != 1 {
		t.Fatal("no AccountBlocked event")
	}
	c, cookies = w.beginLogin(nil)
	expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusUnauthorized)
}

func TestCounterlessAuthenticatorLogsInRepeatedly(t *testing.T) {
	w := newWorld(t)
	sub := w.user("alice@example.com")
	a := webauthntest.New(origin)
	a.Counterless = true
	w.register(w.session(sub), a)
	for range 3 {
		c, cookies := w.beginLogin(nil)
		expect(t, w.finishLogin(c, cookies, a.DiscoverableLogin(t, c.Options)), http.StatusOK)
	}
}

func TestPasskeyTimeoutsAreTheKindTTL(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	timeout := func(opts json.RawMessage) float64 {
		v, _ := publicKeyOf(t, opts)["timeout"].(float64)
		return v
	}
	reg := w.beginRegistration(w.session(sub))
	if timeout(reg.Options) != float64(ceremony.PasskeyRegistration.TTL().Milliseconds()) {
		t.Fatalf("registration timeout %v", timeout(reg.Options))
	}
	c, _ := w.beginLogin(nil)
	if timeout(c.Options) != float64(ceremony.DiscoverablePasskey.TTL().Milliseconds()) {
		t.Fatalf("discoverable timeout %v", timeout(c.Options))
	}
	c, _ = w.beginLogin(map[string]any{routes.FieldIdentifier: "alice@example.com"})
	if timeout(c.Options) != float64(ceremony.UsernameFirstPasskey.TTL().Milliseconds()) {
		t.Fatalf("username-first timeout %v", timeout(c.Options))
	}
	c, cookies := w.beginLogin(nil)
	body := a.DiscoverableLogin(t, c.Options)
	w.clock.Advance(ceremony.DiscoverablePasskey.TTL())
	expect(t, w.finishLogin(c, cookies, body), http.StatusUnauthorized)
}

func TestDisabledAccountGetsFakeOptions(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	if _, err := w.identity.Apply(context.Background(), identity.SetDisabledState{Subject: sub, Disable: true}); err != nil {
		t.Fatal(err)
	}
	c, _ := w.beginLogin(map[string]any{routes.FieldIdentifier: "alice@example.com"})
	if slices.Contains(allowed(t, c.Options), b64(a.Credentials()[0].ID)) {
		t.Fatal("a disabled account's real credential ids were disclosed")
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func allowed(t *testing.T, opts json.RawMessage) []string {
	t.Helper()
	list, _ := publicKeyOf(t, opts)["allowCredentials"].([]any)
	out := make([]string, 0, len(list))
	for _, d := range list {
		m, _ := d.(map[string]any)
		id, _ := m["id"].(string)
		out = append(out, id)
	}
	return out
}
