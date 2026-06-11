package identity_test

// Regression tests for TASK-070: WithLockout(0, ...) must NOT disable brute-force lockout.
//
// Prior to the fix, a non-positive threshold was passed directly to the store, which only
// locks when lockThreshold > 0 — silently turning off the README-advertised lockout.
// The mfa sibling module uses a "non-positive == use default" convention instead, and an
// explicit WithNoAttemptLimit() opt-out. This file pins the aligned behaviour for identity.

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildLockoutService creates a service backed by the real in-memory store, wired with a hasher
// that always reports the wrong password (so every Authenticate call is a failed attempt).
func buildLockoutService(opts ...identity.ServiceOption) (identity.Service, string, string) {
	store := identitymemory.NewStore()
	ctx := context.Background()
	email := "lockout-test@example.com"
	pass := "correct-horse-battery-staple"

	// A hasher that hashes on Register but always fails on Compare (simulates wrong password).
	hasher := &hashertest.MockHasher{
		HashFunc: func(_ context.Context, p string) (string, error) {
			return "stored-" + p, nil
		},
		CompareFunc: func(_ context.Context, _, _ string) error {
			return passwords.ErrInvalidPassword
		},
	}
	policy := &mockPolicy{VerifyFunc: func(_ context.Context, _ string) error { return nil }}

	svc := identity.NewService(store, hasher, policy, opts...)
	_, err := svc.Register(ctx, "", email, pass)
	if err != nil {
		panic("buildLockoutService: Register failed: " + err.Error())
	}
	return svc, email, pass
}

// TestWithLockout_ZeroThreshold_UsesDefault verifies that WithLockout(0, duration) does NOT
// disable lockout — it must fall back to the safe DefaultLockThreshold, not disable the gate.
//
// Before the fix this test fails because threshold 0 is stored verbatim and the store skips
// locking when lockThreshold <= 0.
func TestWithLockout_ZeroThreshold_UsesDefault(t *testing.T) {
	// Configure with threshold=0 and a non-zero duration. Pre-fix this disables lockout.
	svc, email, _ := buildLockoutService(identity.WithLockout(0, time.Hour))
	ctx := context.Background()

	// Fail enough attempts to exceed DefaultLockThreshold.
	for i := 0; i < identity.DefaultLockThreshold; i++ {
		_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
		require.ErrorIs(t, err, identity.ErrInvalidCredentials)
	}

	// The next attempt must be rejected with ErrAccountLocked, not ErrInvalidCredentials.
	// If WithLockout(0, ...) silently disabled the lockout, we would still get
	// ErrInvalidCredentials here — proving the flaw is present.
	_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
	assert.ErrorIs(t, err, identity.ErrAccountLocked,
		"WithLockout(0, ...) must not disable lockout; account must be locked after DefaultLockThreshold failures")
}

// TestWithLockout_ZeroDuration_UsesDefault verifies that WithLockout(threshold, 0) does NOT
// silently result in a zero-duration lock (which would never bite), but falls back to the
// safe DefaultLockDuration.
func TestWithLockout_ZeroDuration_UsesDefault(t *testing.T) {
	// Threshold=1 so we lock after the very first bad attempt; duration=0 is the bad value.
	svc, email, _ := buildLockoutService(identity.WithLockout(1, 0))
	ctx := context.Background()

	// One bad attempt should lock the account.
	_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
	require.ErrorIs(t, err, identity.ErrInvalidCredentials)

	// If duration was stored as 0, LockedUntil would be at/before now and the lock would never
	// fire. With the fix, duration falls back to DefaultLockDuration, so the account IS locked.
	_, err = svc.Authenticate(ctx, "", "password", email, "wrong")
	assert.ErrorIs(t, err, identity.ErrAccountLocked,
		"WithLockout(threshold, 0) must not result in a zero-duration lock; must use DefaultLockDuration")
}

// TestWithNoLockout_DisablesLockout verifies that the explicit WithNoLockout() opt-out actually
// disables lockout. After many failures the account must NOT be locked.
func TestWithNoLockout_DisablesLockout(t *testing.T) {
	svc, email, _ := buildLockoutService(identity.WithNoLockout())
	ctx := context.Background()

	// Exceed the default threshold many times over — no lock must ever be set.
	for i := 0; i < identity.DefaultLockThreshold*3; i++ {
		_, err := svc.Authenticate(ctx, "", "password", email, "wrong")
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials,
			"WithNoLockout must keep returning ErrInvalidCredentials, never ErrAccountLocked (attempt %d)", i+1)
	}
}
