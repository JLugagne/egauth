package keystore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
)

func newKEK(t *testing.T) *keystore.KEK {
	t.Helper()
	k, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	return k
}

// TestNewManager_KEKRequired pins the fail-fast contract: a Manager cannot be built without a
// KEK (envelope encryption is mandatory) or without a Store.
func TestNewManager_KEKRequired(t *testing.T) {
	if _, err := keystore.NewManager(memory.New(), nil); !errors.Is(err, keystore.ErrKEKRequired) {
		t.Fatalf("nil KEK: want ErrKEKRequired, got %v", err)
	}
	if _, err := keystore.NewManager(nil, newKEK(t)); err == nil {
		t.Fatal("nil Store: want error, got nil")
	}
	if _, err := keystore.NewManager(memory.New(), newKEK(t)); err != nil {
		t.Fatalf("valid config: unexpected error %v", err)
	}
}

// TestManager_LifecycleEvents verifies the four lifecycle events fire with the right type and
// tenant.
func TestManager_LifecycleEvents(t *testing.T) {
	ctx := context.Background()
	var got []event.Event
	sink := event.SinkFunc(func(_ context.Context, e event.Event) { got = append(got, e) })

	mgr, err := keystore.NewManager(memory.New(), newKEK(t), keystore.WithEventSink(sink))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := mgr.RenewSigningKey(ctx, "acme"); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := mgr.RevokeTenantKeys(ctx, "acme"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := mgr.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	want := []event.Type{
		keystore.EventTenantProvisioned,
		keystore.EventTenantKeysRenewed,
		keystore.EventTenantKeysRevoked,
		keystore.EventTenantDeleted,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Type != w {
			t.Errorf("event %d: got %q want %q", i, got[i].Type, w)
		}
		if got[i].TenantID != "acme" {
			t.Errorf("event %d: tenant %q want acme", i, got[i].TenantID)
		}
	}
}

// TestManager_ProvisionIdempotentNoDuplicateEvent: a second provision is a no-op and emits no
// second event.
func TestManager_ProvisionIdempotentNoDuplicateEvent(t *testing.T) {
	ctx := context.Background()
	var count int
	sink := event.SinkFunc(func(_ context.Context, e event.Event) {
		if e.Type == keystore.EventTenantProvisioned {
			count++
		}
	})
	mgr, _ := keystore.NewManager(memory.New(), newKEK(t), keystore.WithEventSink(sink))
	_ = mgr.ProvisionTenant(ctx, "acme")
	_ = mgr.ProvisionTenant(ctx, "acme")
	if count != 1 {
		t.Fatalf("provisioned event must fire exactly once, got %d", count)
	}
}

// TestManager_RenewRequiresTenant: renewing a tenant that was never provisioned fails closed.
func TestManager_RenewRequiresTenant(t *testing.T) {
	mgr, _ := keystore.NewManager(memory.New(), newKEK(t))
	if err := mgr.RenewSigningKey(context.Background(), "ghost"); !errors.Is(err, keystore.ErrTenantNotFound) {
		t.Fatalf("want ErrTenantNotFound, got %v", err)
	}
}

// fakeEraser records the tenants it was asked to erase and can be made to fail.
type fakeEraser struct {
	erased []string
	fail   error
}

func (f *fakeEraser) EraseTenant(_ context.Context, tenantID string) error {
	if f.fail != nil {
		return f.fail
	}
	f.erased = append(f.erased, tenantID)
	return nil
}

// TestManager_DeleteFansOutToErasers: DeleteTenant calls every registered eraser.
func TestManager_DeleteFansOutToErasers(t *testing.T) {
	ctx := context.Background()
	e1 := &fakeEraser{}
	e2 := &fakeEraser{}
	mgr, _ := keystore.NewManager(memory.New(), newKEK(t), keystore.WithTenantErasers(e1, e2))
	_ = mgr.ProvisionTenant(ctx, "acme")
	if err := mgr.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for i, e := range []*fakeEraser{e1, e2} {
		if len(e.erased) != 1 || e.erased[0] != "acme" {
			t.Fatalf("eraser %d not invoked for acme: %+v", i, e.erased)
		}
	}
}

// TestManager_DeleteAbortsOnEraserFailure: a downstream eraser failure aborts before crypto is
// removed, so the tenant's keys survive for a retry (resumable delete).
func TestManager_DeleteAbortsOnEraserFailure(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	failing := &fakeEraser{fail: errors.New("boom")}
	mgr, _ := keystore.NewManager(store, newKEK(t), keystore.WithTenantErasers(failing))
	_ = mgr.ProvisionTenant(ctx, "acme")
	if err := mgr.DeleteTenant(ctx, "acme"); err == nil {
		t.Fatal("delete must fail when an eraser fails")
	}
	if exists, _ := store.TenantExists(ctx, "acme"); !exists {
		t.Fatal("crypto must NOT be deleted when a downstream eraser fails (resumable delete)")
	}
}

// TestManager_LazyProvisioning: with WithLazyProvisioning, resolving an unknown tenant auto-
// provisions it; without it, the same resolution fails with ErrTenantNotFound.
func TestManager_LazyProvisioning(t *testing.T) {
	ctx := context.Background()

	strict, _ := keystore.NewManager(memory.New(), newKEK(t))
	if _, err := strict.ActiveSigningKey(ctx, "new-tenant"); !errors.Is(err, keystore.ErrTenantNotFound) {
		t.Fatalf("strict mode: want ErrTenantNotFound, got %v", err)
	}

	lazy, _ := keystore.NewManager(memory.New(), newKEK(t), keystore.WithLazyProvisioning())
	key, err := lazy.ActiveSigningKey(ctx, "new-tenant")
	if err != nil {
		t.Fatalf("lazy mode: unexpected error %v", err)
	}
	if key.KeyID == "" {
		t.Fatal("lazy mode must auto-provision an active key")
	}
}

// TestManager_JWKSNeverLeaksSecret: the JWKS must expose kid/alg metadata but never the secret.
func TestManager_JWKSNeverLeaksSecret(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	mgr, _ := keystore.NewManager(store, newKEK(t))
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	set, err := mgr.JWKS(ctx, "acme")
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 JWK, got %d", len(set.Keys))
	}
	blob, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The marshalled JWKS must NOT contain a "k" field (the symmetric secret).
	if bytes.Contains(blob, []byte("\"k\"")) {
		t.Fatalf("JWKS must never serialize the symmetric secret; got %s", blob)
	}
	jwk := set.Keys[0]
	if jwk.Alg != "HS256" || jwk.Kty != "oct" || jwk.Use != "sig" || jwk.Kid == "" {
		t.Fatalf("unexpected JWK metadata: %+v", jwk)
	}
}

// TestManager_NeedsRenewal: a key is flagged for renewal once it enters the renewal window.
func TestManager_NeedsRenewal(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := t0
	store := memory.New(memory.WithClock(func() time.Time { return clk }))
	mgr, _ := keystore.NewManager(store, newKEK(t), keystore.WithClock(func() time.Time { return clk }))
	if err := mgr.ProvisionTenant(ctx, "acme", func(o *keystore.ProvisionOptions) {
		o.KeyTTL = 24 * time.Hour
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Far from expiry: no renewal needed.
	need, err := mgr.NeedsRenewal(ctx, "acme", time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if need {
		t.Fatal("fresh key should not need renewal")
	}
	// Step to within the window.
	clk = t0.Add(23*time.Hour + 30*time.Minute)
	need, err = mgr.NeedsRenewal(ctx, "acme", time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !need {
		t.Fatal("key within the renewal window must need renewal")
	}
}
