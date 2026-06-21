package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the injectable clock seam (N3): the account-lockout GATE in
// Authenticate must use the service's clock so its expiry is deterministic in
// tests. The lockout STAMP (LockedUntil = now + lockDuration) is computed by the
// store and is out of scope here — this test supplies LockedUntil directly via
// MockStore so both sides share the same injected time base.

func TestWithClock_DeterministicLockoutGate(t *testing.T) {
	ctx := context.Background()
	email := "locked@example.com"
	password := "correct horse battery staple"
	hash := "stored-hash"

	base := time.Unix(1_700_000_000, 0).UTC()
	now := base
	clock := func() time.Time { return now }

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: email}
	store := &storetest.MockStore{
		FindUserByEmailFunc: func(ctx context.Context, tenantID string, e string) (*identity.User, error) {
			return user, nil
		},
		FindIdentityByProviderFunc: func(ctx context.Context, tenantID string, p, pid string) (*identity.Identity, error) {
			lockedUntil := base.Add(5 * time.Minute)
			return &identity.Identity{
				UserID:       user.ID,
				Provider:     "password",
				ProviderID:   email,
				PasswordHash: &hash,
				LockedUntil:  &lockedUntil,
			}, nil
		},
		ResetFailedAttemptsFunc: func(ctx context.Context, tenantID string, id uuid.UUID) error { return nil },
	}

	hasher := &hashertest.MockHasher{
		HashFunc:    func(ctx context.Context, p string) (string, error) { return "decoy", nil },
		CompareFunc: func(ctx context.Context, h, p string) error { return nil },
	}

	svc := identity.NewService(store, hasher, &mockPolicy{}, identity.WithClock(clock))

	// At base+1m the lock (set to base+5m) is still in the future: the gate must reject
	// before the password is ever compared.
	now = base.Add(1 * time.Minute)
	_, err := svc.Authenticate(ctx, "", "password", email, password)
	assert.ErrorIs(t, err, identity.ErrAccountLocked, "account must be locked while clock < LockedUntil")

	// Advance the SAME injected clock past the lock: the gate no longer fires, so the
	// (correct) password is compared and authentication succeeds.
	now = base.Add(6 * time.Minute)
	got, err := svc.Authenticate(ctx, "", "password", email, password)
	require.NoError(t, err, "lock must have expired once clock >= LockedUntil")
	assert.Equal(t, user.ID, got.ID)
}
