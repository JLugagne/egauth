package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/storetest"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pwIdent builds a single password identity for userID carrying the given MustChangePassword flag.
func pwIdent(userID uuid.UUID, mustChange bool) []*identity.Identity {
	h := "stored-hash"
	return []*identity.Identity{{
		ID:                 uuid.Must(uuid.NewV7()),
		UserID:             userID,
		Provider:           "password",
		PasswordHash:       &h,
		MustChangePassword: mustChange,
	}}
}

// PasswordChangeRequired is gated solely on the explicit MustChangePassword flag set by
// temporary/one-time provisioning. egauth deliberately does NOT do age-based rotation
// (NIST SP 800-63B discourages fixed-interval expiry), so password age never sets the flag.
func TestPasswordChangeRequired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV7())

	storeReturning := func(idents []*identity.Identity) *storetest.MockStore {
		return &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				assert.Equal(t, userID, id)
				return idents, nil
			},
		}
	}

	t.Run("flag set returns true", func(t *testing.T) {
		store := storeReturning(pwIdent(userID, true))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil)

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.True(t, got, "an explicit MustChangePassword flag must require a change")
	})

	t.Run("flag unset returns false", func(t *testing.T) {
		store := storeReturning(pwIdent(userID, false))
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil)

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "an unflagged password is never forced to change (no age-based rotation)")
	})

	t.Run("oauth-only account is never flagged", func(t *testing.T) {
		store := storeReturning([]*identity.Identity{{
			ID: uuid.Must(uuid.NewV7()), UserID: userID, Provider: "google", ProviderID: "sub-123",
		}})
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil)

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		require.NoError(t, err)
		assert.False(t, got, "an account with no password identity has nothing to force")
	})

	t.Run("store error is propagated", func(t *testing.T) {
		sentinel := errors.New("boom")
		store := &storetest.MockStore{
			FindIdentitiesByUserIDFunc: func(ctx context.Context, tenantID string, id uuid.UUID) ([]*identity.Identity, error) {
				return nil, sentinel
			},
		}
		svc := identity.NewService(store, &hashertest.MockHasher{}, nil)

		got, err := svc.PasswordChangeRequired(ctx, "", userID)
		assert.ErrorIs(t, err, sentinel)
		assert.False(t, got)
	})
}
