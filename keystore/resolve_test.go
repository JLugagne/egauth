package keystore_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/memory"
)

func newResolveManager(t *testing.T, store keystore.Store, sink event.Sink) *keystore.Manager {
	t.Helper()
	kek, err := keystore.NewKEK(bytes.Repeat([]byte("k"), keystore.KEKKeyLength))
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	mgr, err := keystore.NewManager(store, kek, keystore.WithEventSink(sink))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// TestVerificationKeys_SkipsUnreadableKeyRow asserts one key row that cannot be opened (sealed
// under a different KEK, or corrupted at rest) does not take the whole tenant's verification set
// down with it: the readable keys are still returned and the bad row is surfaced as an event.
func TestVerificationKeys_SkipsUnreadableKeyRow(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	var got []event.Event
	mgr := newResolveManager(t, store, event.SinkFunc(func(ctx context.Context, e event.Event) {
		got = append(got, e)
	}))
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	good, err := mgr.ActiveSigningKey(ctx, "acme")
	if err != nil {
		t.Fatalf("ActiveSigningKey: %v", err)
	}
	corrupt := keystore.SigningKey{
		KeyID:     "corrupt",
		Secret:    []byte("not-sealed-with-this-kek"),
		CreatedAt: time.Now().Add(-time.Hour),
	}
	if err := store.PutSigningKey(ctx, "acme", corrupt); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}

	keys, err := mgr.VerificationKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("one unreadable row must not fail the whole verification set: %v", err)
	}
	if _, ok := keys[good.KeyID]; !ok {
		t.Fatal("the readable key must still be in the verification set")
	}
	if _, ok := keys["corrupt"]; ok {
		t.Fatal("the unreadable key must be skipped, not returned with sealed bytes")
	}

	var emitted bool
	for _, e := range got {
		if e.Type != keystore.EventKeyUnreadable {
			continue
		}
		emitted = true
		if e.TenantID != "acme" {
			t.Fatalf("event TenantID = %q, want acme", e.TenantID)
		}
		if e.Attrs["key_id"] != "corrupt" {
			t.Fatalf("event key_id = %v, want corrupt", e.Attrs["key_id"])
		}
		if e.Err == nil {
			t.Fatal("event must carry the underlying open error")
		}
	}
	if !emitted {
		t.Fatalf("an unreadable key row must be surfaced as %s", keystore.EventKeyUnreadable)
	}
}

// TestJWKS_SkipsUnreadableKeyRow asserts the published key set degrades the same way, so a single
// bad row cannot take down /.well-known/jwks.json.
func TestJWKS_SkipsUnreadableKeyRow(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	mgr := newResolveManager(t, store, nil)
	if err := mgr.ProvisionTenant(ctx, "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := store.PutSigningKey(ctx, "acme", keystore.SigningKey{
		KeyID:     "corrupt",
		Secret:    []byte("not-sealed-with-this-kek"),
		CreatedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("PutSigningKey: %v", err)
	}
	set, err := mgr.JWKS(ctx, "acme")
	if err != nil {
		t.Fatalf("JWKS must skip the unreadable row: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWKS should publish the 1 readable key, got %d", len(set.Keys))
	}
}
