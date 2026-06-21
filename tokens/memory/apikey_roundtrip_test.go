package memory

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryAPIKeyTypeRoundTrip proves the in-memory store keeps parity with the API-key model:
// it persists and returns Type and CreatedBy for both key kinds, never persists the clear-text
// token, and keeps the records isolated per tenant.
func TestMemoryAPIKeyTypeRoundTrip(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"

	t.Run("PAT round-trips Type and CreatedBy", func(t *testing.T) {
		store := NewStore[struct{}]()
		owner := uuid.Must(uuid.NewV7())
		exp := time.Now().Add(24 * time.Hour)

		in := &tokens.APIKey[struct{}]{
			ID:        uuid.Must(uuid.NewV7()),
			TenantID:  tenant,
			Prefix:    "sk_pat_",
			Token:     "sk_pat_cleartext",
			Hash:      "pat-hash",
			ExpiresAt: &exp,
			Type:      tokens.KeyTypePAT,
			CreatedBy: owner,
			Claims:    tokens.Claims[struct{}]{Subject: owner, TenantID: tenant, Scopes: []string{"repo:read"}},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenant, in))

		got, err := store.FindAPIKeyByHash(ctx, tenant, "pat-hash")
		require.NoError(t, err)
		assert.Equal(t, tokens.KeyTypePAT, got.Type)
		assert.Equal(t, owner, got.CreatedBy)
		assert.Equal(t, owner, got.Claims.Subject)
		assert.Equal(t, []string{"repo:read"}, got.Claims.Scopes)
		assert.Empty(t, got.Token, "the clear-text token must never be persisted")
	})

	t.Run("Service round-trips Type and CreatedBy distinct from Subject", func(t *testing.T) {
		store := NewStore[struct{}]()
		creator := uuid.Must(uuid.NewV7())
		keyID := uuid.Must(uuid.NewV7())

		in := &tokens.APIKey[struct{}]{
			ID:        keyID,
			TenantID:  tenant,
			Prefix:    "sk_svc_",
			Token:     "sk_svc_cleartext",
			Hash:      "svc-hash",
			Type:      tokens.KeyTypeService,
			CreatedBy: creator,
			Claims:    tokens.Claims[struct{}]{Subject: keyID, TenantID: tenant},
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenant, in))

		got, err := store.FindAPIKeyByHash(ctx, tenant, "svc-hash")
		require.NoError(t, err)
		assert.Equal(t, tokens.KeyTypeService, got.Type)
		assert.Equal(t, creator, got.CreatedBy, "the human creator is recorded for attribution")
		assert.Equal(t, keyID, got.Claims.Subject, "a service token's subject is its own key ID")
		assert.NotEqual(t, creator, got.Claims.Subject, "the creator is distinct from the service identity")
		assert.Empty(t, got.Token)
	})

	t.Run("a key saved under one tenant is invisible to another", func(t *testing.T) {
		store := NewStore[struct{}]()
		in := &tokens.APIKey[struct{}]{
			ID:        uuid.Must(uuid.NewV7()),
			TenantID:  tenant,
			Hash:      "scoped-hash",
			Type:      tokens.KeyTypeService,
			CreatedBy: uuid.Must(uuid.NewV7()),
		}
		require.NoError(t, store.SaveAPIKey(ctx, tenant, in))

		_, err := store.FindAPIKeyByHash(ctx, "other-tenant", "scoped-hash")
		assert.ErrorIs(t, err, tokens.ErrAPIKeyNotFound)
	})
}
