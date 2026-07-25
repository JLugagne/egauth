package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MyCustomClaims struct {
	Plan    string `json:"plan"`
	IsAdmin bool   `json:"is_admin"`
}

func TestJWTIssuerVerifier_Contract(t *testing.T) {
	refreshTokens := make(map[string]*tokens.RefreshToken)
	apiKeys := make(map[string]*tokens.APIKey[MyCustomClaims])

	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			rtCopy := *rt
			refreshTokens[rt.Hash] = &rtCopy
			return nil
		},
		FindRefreshTokenFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
			rt, ok := refreshTokens[tokenHash]
			if !ok {
				return nil, tokens.ErrRefreshTokenNotFound
			}
			return rt, nil
		},
		SaveAPIKeyFunc: func(ctx context.Context, tenantID string, key *tokens.APIKey[MyCustomClaims]) error {
			apiKeys[key.Hash] = key
			return nil
		},
		FindAPIKeyByHashFunc: func(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[MyCustomClaims], error) {
			key, ok := apiKeys[tokenHash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			return key, nil
		},
	}

	cfg := jwt.Config[MyCustomClaims]{
		Store:      mockStore,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	issuertest.IssuerVerifierContractTesting[MyCustomClaims](t, svc, svc, MyCustomClaims{Plan: "pro", IsAdmin: true})
}

// newIssueKeyService builds a Service whose in-memory store captures every saved API key,
// keyed by its hash, so a test can both verify the returned key and inspect what was persisted.
func newIssueKeyService(t *testing.T) (*jwt.Service[MyCustomClaims], map[string]*tokens.APIKey[MyCustomClaims]) {
	t.Helper()
	saved := make(map[string]*tokens.APIKey[MyCustomClaims])
	store := &storetest.MockStore[MyCustomClaims]{
		SaveAPIKeyFunc: func(_ context.Context, _ string, key *tokens.APIKey[MyCustomClaims]) error {
			cp := *key
			saved[key.Hash] = &cp
			return nil
		},
		FindAPIKeyByHashFunc: func(_ context.Context, _ string, hash string) (*tokens.APIKey[MyCustomClaims], error) {
			key, ok := saved[hash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			return key, nil
		},
	}
	cfg := jwt.Config[MyCustomClaims]{
		Store:      store,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	return jwt.New[MyCustomClaims](cfg), saved
}

// TestIssueAPIKey covers the per-type issuance contract: a PAT's subject is the user, a
// Service token's subject is its own key ID, both record the type and the human creator, and
// the issuer uses only the caller-supplied scopes (it never copies the user's stored roles).
func TestIssueAPIKey(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-abc"

	t.Run("PAT subject is the creating user", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		// A PAT acts as its creator: the user issues their own token (Subject defaults to createdBy
		// when left unset), so Subject == CreatedBy == the user.
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   []string{"repo:read"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypePAT, key.Type)
		assert.Equal(t, userID, key.CreatedBy)
		assert.Equal(t, userID, key.Claims.Subject, "a PAT acts as its creator, so its subject is the creating user")

		// The persisted row mirrors the returned key.
		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, tokens.KeyTypePAT, stored.Type)
		assert.Equal(t, userID, stored.CreatedBy)
		assert.Equal(t, userID, stored.Claims.Subject)
	})

	t.Run("PAT with Subject different from createdBy is rejected", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())
		otherUser := uuid.Must(uuid.NewV7())

		_, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, creatorID, tokens.Claims[MyCustomClaims]{
			Subject:  otherUser, // names a different user than the creator
			TenantID: tenant,
			Scopes:   []string{"repo:read"},
		})
		require.ErrorIs(t, err, jwt.ErrPATSubjectMismatch,
			"a PAT naming a different user than its creator must be rejected (else it would survive that user's DisableUser)")
	})

	t.Run("Service subject is the key's own ID, distinct from the creator", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		key, err := svc.IssueAPIKey(ctx, "sk_svc_", tokens.KeyTypeService, creatorID, tokens.Claims[MyCustomClaims]{
			// A caller-supplied subject must be ignored for a Service token.
			Subject:  uuid.Must(uuid.NewV7()),
			TenantID: tenant,
			Scopes:   []string{"ingest:write"},
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, tokens.KeyTypeService, key.Type)
		assert.Equal(t, creatorID, key.CreatedBy)
		assert.Equal(t, key.ID, key.Claims.Subject, "a Service token's subject is its own key ID")
		assert.NotEqual(t, creatorID, key.Claims.Subject, "the creator is distinct from the service identity")

		stored := saved[key.Hash]
		require.NotNil(t, stored)
		assert.Equal(t, key.ID, stored.Claims.Subject)
		assert.Equal(t, creatorID, stored.CreatedBy)
	})

	t.Run("empty keyType is rejected, never silently issued as a machine identity", func(t *testing.T) {
		svc, saved := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		_, err := svc.IssueAPIKey(ctx, "sk_", tokens.KeyType(""), creatorID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
		})
		require.ErrorIs(t, err, jwt.ErrInvalidKeyType, "an empty keyType must be rejected outright, not silently defaulted")
		assert.Empty(t, saved, "a rejected IssueAPIKey call must not persist anything")
	})

	t.Run("unknown keyType is rejected", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		creatorID := uuid.Must(uuid.NewV7())

		_, err := svc.IssueAPIKey(ctx, "sk_", tokens.KeyType("bogus"), creatorID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
		})
		require.ErrorIs(t, err, jwt.ErrInvalidKeyType)
	})

	t.Run("no silent role copy: only caller-supplied scopes are used", func(t *testing.T) {
		svc, _ := newIssueKeyService(t)
		userID := uuid.Must(uuid.NewV7())

		// The user is powerful (admin), but the PAT is issued with a deliberately narrow set.
		// The issuer must NOT widen the key's authority to the user's roles.
		narrow := []string{"repo:read"}
		key, err := svc.IssueAPIKey(ctx, "sk_pat_", tokens.KeyTypePAT, userID, tokens.Claims[MyCustomClaims]{
			TenantID: tenant,
			Scopes:   narrow,
			Roles:    []string{"viewer"},
		})
		require.NoError(t, err)

		assert.Equal(t, narrow, key.Claims.Scopes, "scopes must be exactly those passed by the caller")
		assert.Equal(t, []string{"viewer"}, key.Claims.Roles, "roles must be exactly those passed by the caller")
		assert.NotContains(t, key.Claims.Roles, "admin", "the user's broader stored roles must never be copied onto the key")
	})
}

func TestJWTIssuerVerifier_EdgeCases(t *testing.T) {
	ctx := context.Background()
	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
			return nil
		},
	}

	// InsecureAllowWeakKey is set because this test intentionally uses a short key
	// to exercise expiry/signature-mismatch edge cases, not key-strength behaviour.
	cfg := jwt.Config[MyCustomClaims]{
		Store:                mockStore,
		SecretKey:            "secret",
		Issuer:               "test",
		AccessTTL:            -1 * time.Minute, // Expired immediately
		RefreshTTL:           24 * time.Hour,
		InsecureAllowWeakKey: true,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	t.Run("Expired token returns ErrTokenExpired", func(t *testing.T) {
		claims := tokens.Claims[MyCustomClaims]{
			Subject: uuid.Must(uuid.NewV7()),
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)

		_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired)
	})

	t.Run("Invalid signature returns ErrInvalidToken", func(t *testing.T) {
		// Create a token with a different secret; InsecureAllowWeakKey bypasses length check.
		otherSvc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
			Store:                mockStore,
			SecretKey:            "different-secret",
			AccessTTL:            1 * time.Hour,
			InsecureAllowWeakKey: true,
		})

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.Must(uuid.NewV7())})
		require.NoError(t, err)

		_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
}
