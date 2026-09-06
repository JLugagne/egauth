package tokens_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth"
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
		assert.Equal(t, tokens.KeyType("user"), tokens.KeyTypeUser)
		assert.Equal(t, tokens.KeyType("service"), tokens.KeyTypeService)
		assert.Equal(t, tokens.KeyType("system"), tokens.KeyTypeSystem)
	})

	t.Run("KeyType Valid method validates allowed principal types", func(t *testing.T) {
		validTypes := []tokens.KeyType{
			tokens.KeyTypeUser,
			tokens.KeyTypeService,
			tokens.KeyTypeSystem,
			tokens.KeyTypePAT,
		}
		for _, kt := range validTypes {
			assert.True(t, kt.Valid(), "expected %q to be valid", kt)
		}

		invalidTypes := []tokens.KeyType{
			"",
			"invalid",
			"admin",
			"root",
			" ",
		}
		for _, kt := range invalidTypes {
			assert.False(t, kt.Valid(), "expected %q to be invalid", kt)
		}
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

	t.Run("User key carries Type and CreatedBy", func(t *testing.T) {
		ownerID := uuid.New()
		exp := time.Now().Add(24 * time.Hour)
		key := tokens.APIKey[struct{}]{
			ID:        uuid.New(),
			TenantID:  "tenant-abc",
			Prefix:    "sk_usr_",
			Token:     "sk_usr_cleartext",
			Hash:      "sha256hash",
			ExpiresAt: &exp,
			Type:      tokens.KeyTypeUser,
			CreatedBy: ownerID,
			Claims: tokens.Claims[struct{}]{
				Subject: ownerID,
			},
		}
		require.Equal(t, tokens.KeyTypeUser, key.Type)
		assert.Equal(t, ownerID, key.CreatedBy)
		assert.Equal(t, "user", string(key.Type))

		actor := tokens.ActorFromAPIKey(&key)
		assert.Equal(t, egauth.User, actor.Kind)
		assert.Equal(t, ownerID, actor.UserID)
	})

	t.Run("System key carries Type and CreatedBy distinct from Subject", func(t *testing.T) {
		creatorID := uuid.New()
		keyID := uuid.New()
		key := tokens.APIKey[struct{}]{
			ID:        keyID,
			TenantID:  "tenant-abc",
			Prefix:    "sk_sys_",
			Token:     "sk_sys_cleartext",
			Hash:      "sha256hash",
			Type:      tokens.KeyTypeSystem,
			CreatedBy: creatorID,
			Claims: tokens.Claims[struct{}]{
				Subject: keyID,
			},
		}
		require.Equal(t, tokens.KeyTypeSystem, key.Type)
		assert.Equal(t, creatorID, key.CreatedBy)
		assert.Equal(t, keyID, key.Claims.Subject)
		assert.Equal(t, "system", string(key.Type))

		actor := tokens.ActorFromAPIKey(&key)
		assert.Equal(t, egauth.Service, actor.Kind)
		assert.Equal(t, uuid.Nil, actor.UserID)
		assert.Equal(t, keyID, actor.KeyID)
	})

	t.Run("zero-value APIKey has empty Type and nil CreatedBy", func(t *testing.T) {
		var key tokens.APIKey[struct{}]
		assert.Equal(t, tokens.KeyType(""), key.Type)
		assert.Equal(t, uuid.UUID{}, key.CreatedBy)
	})
}
