package passkeysvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/passkeysvc"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/webauthntest"
)

func (w *world) pendingFor(sub core.Subject) core.Pending {
	w.t.Helper()
	st, err := accounts{identity: w.identity, unverified: w.unverified}.AccountState(context.Background(), sub)
	if err != nil {
		w.t.Fatal(err)
	}
	p, err := core.NewPending(sub.Tenant, core.RememberRequested, redirect.Target{}, core.TransportCookies, core.RememberUserChoice, w.clock.Now())
	if err != nil {
		w.t.Fatal(err)
	}
	if p, err = p.Bind(sub, st); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) stepUp(p core.Pending, a *webauthntest.Authenticator) (core.Pending, core.Verified, error) {
	w.t.Helper()
	ch, err := w.svc.BeginStepUp(context.Background(), p)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.svc.FinishStepUp(context.Background(), core.TenantID{}, ch.Handle, a.Login(w.t, ch.Options))
}

func TestStepUpYieldsPasskeyStepUp(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	p := w.pendingFor(sub)
	puts := w.ceremonies.puts.Load()
	got, v, err := w.stepUp(p, a)
	if err != nil {
		t.Fatal(err)
	}
	if w.ceremonies.puts.Load() != puts+1 {
		t.Fatal("the step-up begin did not store one MFAPasskey record")
	}
	if !slices.Equal(v.Factors(), []core.Factor{core.FactorPasskeyStepUp}) || v.Identifies() || v.Subject() != sub {
		t.Fatalf("verified %v identifies=%v", v.Factors(), v.Identifies())
	}
	if !got.RememberMe() {
		t.Fatal("the sealed Pending was not replayed")
	}
	if _, _, err := w.svc.FinishStepUp(context.Background(), core.TenantID{}, mustHandle(t, w, p), nil); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("garbage assertion = %v", err)
	}
}

func mustHandle(t *testing.T, w *world, p core.Pending) string {
	t.Helper()
	ch, err := w.svc.BeginStepUp(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return ch.Handle
}

func TestStepUpWithThePrimaryCredentialStaysSingleFactor(t *testing.T) {
	w := newWorld(t)
	sub, phone := w.enrolled("alice@example.com")
	key := webauthntest.New(origin)
	w.register(w.session(sub), key)
	c, cookies := w.beginLogin(map[string]any{"identifier": "alice@example.com"})
	expect(t, w.finishLogin(c, cookies, phone.Login(t, c.Options)), 200)
	primary := w.lastCompletion()
	st, err := accounts{identity: w.identity, unverified: w.unverified}.AccountState(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	withPK := primary.added
	_, same, err := w.stepUp(withPK, phone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withPK.Add(same, st); !errors.Is(err, core.ErrSameCredential) {
		t.Fatalf("same-credential step-up Add = %v, want ErrSameCredential", err)
	}
	_, other, err := w.stepUp(withPK, key)
	if err != nil {
		t.Fatal(err)
	}
	both, err := withPK.Add(other, st)
	if err != nil {
		t.Fatalf("distinct-credential step-up Add = %v", err)
	}
	if !slices.Contains(both.Factors(), core.FactorPasskeyStepUp) {
		t.Fatal("pk_stepup missing")
	}
}

func TestStepUpRefusals(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	other, mallory := w.enrolled("mallory@example.com")
	ctx := context.Background()
	if _, err := w.svc.BeginStepUp(ctx, w.pendingFor(w.user("nokey@example.com"))); !errors.Is(err, passkeysvc.ErrNoPasskey) {
		t.Fatalf("no credential: %v", err)
	}
	unbound, err := core.NewPending(core.TenantID{}, core.RememberDeclined, redirect.Target{}, core.TransportCookies, core.RememberUserChoice, w.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.BeginStepUp(ctx, unbound); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("unbound pending: %v", err)
	}
	ch, err := w.svc.BeginStepUp(ctx, w.pendingFor(sub))
	if err != nil {
		t.Fatal(err)
	}
	pk := publicKeyOf(t, ch.Options)
	pk["allowCredentials"] = []map[string]any{{"type": "public-key", "id": b64(mallory.Credentials()[0].ID)}}
	foreign, err := jsonOf(map[string]any{"publicKey": pk})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.FinishStepUp(ctx, core.TenantID{}, ch.Handle, mallory.Login(t, foreign)); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("foreign credential: %v", err)
	}
	if w.credentials(other)[0].SignCount != 0 {
		t.Fatal("a foreign step-up advanced the counter")
	}
	if _, _, err := w.svc.FinishStepUp(ctx, core.TenantID{}, ch.Handle, a.Login(t, ch.Options)); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("the record survived a failed finish: %v", err)
	}
	if w.sink.count(event.MFAVerificationFailed) == 0 {
		t.Fatal("no MFAVerificationFailed event")
	}
	ch, err = w.svc.BeginStepUp(ctx, w.pendingFor(sub))
	if err != nil {
		t.Fatal(err)
	}
	body := a.Login(t, ch.Options)
	if err := w.passkeys.Suspend(ctx, sub, a.Credentials()[0].ID, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.FinishStepUp(ctx, core.TenantID{}, ch.Handle, body); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("suspended credential: %v", err)
	}
	if _, err := w.svc.BeginStepUp(ctx, w.pendingFor(sub)); !errors.Is(err, passkeysvc.ErrNoPasskey) {
		t.Fatalf("only suspended credentials: %v", err)
	}
}

func TestStepUpRecordExpiresWithTheKindTTL(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	ch, err := w.svc.BeginStepUp(context.Background(), w.pendingFor(sub))
	if err != nil {
		t.Fatal(err)
	}
	body := a.Login(t, ch.Options)
	if v, _ := publicKeyOf(t, ch.Options)["timeout"].(float64); v != float64(ceremony.MFAPasskey.TTL().Milliseconds()) {
		t.Fatalf("timeout %v", v)
	}
	w.clock.Advance(ceremony.MFAPasskey.TTL())
	if _, _, err := w.svc.FinishStepUp(context.Background(), core.TenantID{}, ch.Handle, body); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("expired record: %v", err)
	}
}

func jsonOf(v any) ([]byte, error) { return json.Marshal(v) }

func TestStepUpHandleOfAnotherTenantIsRefused(t *testing.T) {
	w := newWorld(t)
	sub, a := w.enrolled("alice@example.com")
	ch, err := w.svc.BeginStepUp(context.Background(), w.pendingFor(sub))
	if err != nil {
		t.Fatal(err)
	}
	other, err := core.ParseTenantID("other")
	if err != nil {
		t.Fatal(err)
	}
	body := a.Login(t, ch.Options)
	if _, _, err := w.svc.FinishStepUp(context.Background(), other, ch.Handle, body); !errors.Is(err, passkeysvc.ErrPasskeyRejected) {
		t.Fatalf("foreign tenant: %v", err)
	}
	if _, _, err := w.svc.FinishStepUp(context.Background(), core.TenantID{}, ch.Handle, body); err != nil {
		t.Fatalf("a foreign-tenant attempt consumed the record: %v", err)
	}
}
