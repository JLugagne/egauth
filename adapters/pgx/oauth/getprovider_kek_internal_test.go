package pgx

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/keystore"
)

// countingKEK records how many times Open (the client_secret decrypt) is invoked and can be
// configured to fail on a chosen Open call, standing in for a transient KEK/KMS blip.
type countingKEK struct {
	openCalls   int
	failOnOpenN int
	// lastSealContext / lastOpenContext record the SecretContext each call was given, so a test can
	// pin the binding the store must supply.
	lastSealContext keystore.SecretContext
	lastOpenContext keystore.SecretContext
}

func (k *countingKEK) Seal(_ context.Context, sc keystore.SecretContext, plaintext []byte) ([]byte, error) {
	k.lastSealContext = sc
	return plaintext, nil
}

func (k *countingKEK) Open(_ context.Context, sc keystore.SecretContext, ciphertext []byte) ([]byte, error) {
	k.lastOpenContext = sc
	k.openCalls++
	if k.failOnOpenN != 0 && k.openCalls == k.failOnOpenN {
		return nil, errors.New("countingKEK: simulated transient decrypt failure")
	}
	return ciphertext, nil
}

// TestGetProviderCacheHitSkipsDecrypt proves that a cache HIT returns without touching the KEK.
// Two GetProvider calls for the same unchanged row must decrypt the client_secret at most once:
// the second call is served from the provider cache and must not perform a KEK round-trip.
func TestGetProviderCacheHitSkipsDecrypt(t *testing.T) {
	q := &countingQuerier{}
	kek := &countingKEK{}
	store := NewStore(q, kek)
	ctx := context.Background()

	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("first GetProvider: %v", err)
	}
	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("second GetProvider: %v", err)
	}

	if kek.openCalls > 1 {
		t.Errorf("expected at most 1 KEK Open across two GetProvider calls, got %d; a cache hit must not decrypt", kek.openCalls)
	}
}

// TestGetProviderCacheHitSurvivesKEKFailure proves that a transient KEK failure does not take down
// a login the warm cache should have served: once a provider is cached, a second GetProvider for
// the same unchanged row returns the cached provider even if the KEK now fails to Open.
func TestGetProviderCacheHitSurvivesKEKFailure(t *testing.T) {
	q := &countingQuerier{}
	kek := &countingKEK{failOnOpenN: 2}
	store := NewStore(q, kek)
	ctx := context.Background()

	p1, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("first GetProvider: %v", err)
	}
	p2, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("second GetProvider returned error on a warm cache during a transient KEK blip: %v", err)
	}
	if p1 != p2 {
		t.Errorf("cache hit returned a distinct provider instance (%p vs %p)", p1, p2)
	}
}
