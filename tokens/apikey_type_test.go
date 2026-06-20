package tokens_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIKeyType verifies that APIKey carries Type and CreatedBy and that the
// KeyTypePAT / KeyTypeService constants have the expected wire values.
func TestAPIKeyType(t *testing.T) {
	t.Run("KeyType constants have expected wire values", func(t *testing.T) {
		assert.Equal(t, tokens.KeyType("pat"), tokens.KeyTypePAT)
		assert.Equal(t, tokens.KeyType("service"), tokens.KeyTypeService)
	})

	t.Run("PAT key carries Type and CreatedBy", func(t *testing.T) {
		ownerID := uuid.New()
		exp := time.Now().Add(24 * time.Hour)
		key := tokens.APIKey[struct{}]{
			ID:        uuid.New(),
			TenantID:  "tenant-abc",
			Prefix:    "sk_pat_",
			Token:     "sk_pat_cleartext",
			Hash:      "sha256hash",
			ExpiresAt: &exp,
			Type:      tokens.KeyTypePAT,
			CreatedBy: ownerID,
		}
		require.Equal(t, tokens.KeyTypePAT, key.Type)
		assert.Equal(t, ownerID, key.CreatedBy)
		assert.Equal(t, "pat", string(key.Type))
	})

	t.Run("Service key carries Type and CreatedBy distinct from Subject", func(t *testing.T) {
		creatorID := uuid.New()
		// For a Service token, Claims.Subject is the key's own ID, not the creator.
		keyID := uuid.New()
		key := tokens.APIKey[struct{}]{
			ID:        keyID,
			TenantID:  "tenant-abc",
			Prefix:    "sk_svc_",
			Token:     "sk_svc_cleartext",
			Hash:      "sha256hash",
			Type:      tokens.KeyTypeService,
			CreatedBy: creatorID,
			Claims: tokens.Claims[struct{}]{
				Subject: keyID, // service token subject == key's own ID
			},
		}
		require.Equal(t, tokens.KeyTypeService, key.Type)
		assert.Equal(t, creatorID, key.CreatedBy)
		assert.Equal(t, keyID, key.Claims.Subject, "service token subject must be the key's own ID")
		assert.NotEqual(t, creatorID, key.Claims.Subject, "creator is distinct from the service identity")
		assert.Equal(t, "service", string(key.Type))
	})

	t.Run("zero-value APIKey has empty Type and nil CreatedBy", func(t *testing.T) {
		var key tokens.APIKey[struct{}]
		assert.Equal(t, tokens.KeyType(""), key.Type)
		assert.Equal(t, uuid.UUID{}, key.CreatedBy)
	})
}
