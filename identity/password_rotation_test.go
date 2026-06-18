package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedNow returns a deterministic clock for the rotation age computation.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// pwIdentAt builds a single password identity for userID with the given PasswordChangedAt and flag.
func pwIdentAt(userID uuid.UUID, changedAt time.Time, mustChange bool) []*identity.Identity {
	h := "stored-hash"
	return []*identity.Identity{{
		ID:                 uuid.Must(uuid.NewV7()),
		UserID:             userID,
		Provider:           "password",
		PasswordHash:       &h,
		PasswordChangedAt:  changedAt,
		MustChangePassword: mustChange,
	}}
}

func TestPasswordChangeRequired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	const maxAge = 90 * 24 * time.Hour

	storeReturning := func(idents []*identity.Identity) *storetest.MockStore {
		return &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				assert.Equal(t, userID, id)
				return idents, nil
			},
		}
	}

	t.Run("flag set returns true even with rotation off", func(t *testing.T) {
		store := storeReturning(pwIdentAt(userID, now, true))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil, identity.WithClock(fixedNow(now)))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.True(t, got, "an explicit MustChangePassword flag must require a change")
	})

	t.Run("aged past max returns true when rotation enabled", func(t *testing.T) {
		changedAt := now.Add(-maxAge - time.Hour) // older than maxAge
		store := storeReturning(pwIdentAt(userID, changedAt, false))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)), identity.WithPasswordRotation(maxAge))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.True(t, got, "a password older than maxAge must require a change")
	})

	t.Run("within age returns false when rotation enabled", func(t *testing.T) {
		changedAt := now.Add(-maxAge + time.Hour) // younger than maxAge
		store := storeReturning(pwIdentAt(userID, changedAt, false))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)), identity.WithPasswordRotation(maxAge))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "a password younger than maxAge must not require a change")
	})

	t.Run("resolver opt-out returns false even when aged past the global max", func(t *testing.T) {
		changedAt := now.Add(-maxAge - time.Hour) // would be due under the global default
		store := storeReturning(pwIdentAt(userID, changedAt, false))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)),
			identity.WithPasswordRotation(maxAge),
			identity.WithPasswordRotationResolver(func(tenantID string) (time.Duration, bool) {
				return 0, false // this tenant opts out of rotation
			}))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "a tenant resolver opt-out overrides the global default")
	})

	t.Run("default off returns false even for an ancient password", func(t *testing.T) {
		changedAt := now.Add(-10 * 365 * 24 * time.Hour) // a decade old
		store := storeReturning(pwIdentAt(userID, changedAt, false))
		// No WithPasswordRotation and no resolver: rotation is off by default.
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil, identity.WithClock(fixedNow(now)))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "with rotation unconfigured the flag is never set by age")
	})

	t.Run("legacy zero PasswordChangedAt is not due", func(t *testing.T) {
		store := storeReturning(pwIdentAt(userID, time.Time{}, false)) // zero stamp
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)), identity.WithPasswordRotation(maxAge))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "a legacy zero PasswordChangedAt must not be treated as due")
	})

	t.Run("resolver override tightens the max age", func(t *testing.T) {
		changedAt := now.Add(-2 * time.Hour) // young under global, old under tenant override
		store := storeReturning(pwIdentAt(userID, changedAt, false))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)),
			identity.WithPasswordRotation(maxAge),
			identity.WithPasswordRotationResolver(func(tenantID string) (time.Duration, bool) {
				return time.Hour, true // this tenant rotates every hour
			}))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.True(t, got, "the resolver max age overrides the global default")
	})

	t.Run("oauth-only account is never flagged", func(t *testing.T) {
		store := storeReturning([]*identity.Identity{{
			ID: uuid.Must(uuid.NewV7()), UserID: userID, Provider: "google", ProviderID: "sub-123",
		}})
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil,
			identity.WithClock(fixedNow(now)), identity.WithPasswordRotation(maxAge))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "an account with no password identity has nothing to rotate")
	})

	t.Run("store error is propagated", func(t *testing.T) {
		sentinel := errors.New("boom")
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return nil, sentinel
			},
		}
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil, identity.WithClock(fixedNow(now)))

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		assert.ErrorIs(t, err, sentinel)
		assert.False(t, got)
	})
}
