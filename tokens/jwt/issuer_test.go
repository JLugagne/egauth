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
			Subject: uuid.New(),
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

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.New()})
		require.NoError(t, err)

		_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
}
