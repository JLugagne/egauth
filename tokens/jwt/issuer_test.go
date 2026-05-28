package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/JLugagne/libauth/tokens/jwt"
	"github.com/JLugagne/libauth/tokens/issuertest"
	"github.com/JLugagne/libauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MyCustomClaims struct {
	Plan    string `json:"plan"`
	IsAdmin bool   `json:"is_admin"`
}

func TestJWTIssuerVerifier_Contract(t *testing.T) {
	refreshTokens := make(map[string]uuid.UUID)
	apiKeys := make(map[string]*tokens.APIKey[MyCustomClaims])

	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error {
			refreshTokens[tokenHash] = userID
			return nil
		},
		FindRefreshTokenByHashFunc: func(ctx context.Context, tokenHash string, opts ...tokens.Option) (uuid.UUID, time.Time, error) {
			userID, ok := refreshTokens[tokenHash]
			if !ok {
				return uuid.Nil, time.Time{}, tokens.ErrRefreshTokenNotFound
			}
			return userID, time.Now().Add(time.Hour), nil
		},
		SaveAPIKeyFunc: func(ctx context.Context, key *tokens.APIKey[MyCustomClaims], opts ...tokens.Option) error {
			apiKeys[key.Hash] = key
			return nil
		},
		FindAPIKeyByHashFunc: func(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[MyCustomClaims], error) {
			key, ok := apiKeys[tokenHash]
			if !ok {
				return nil, tokens.ErrAPIKeyNotFound
			}
			return key, nil
		},
	}

	cfg := jwt.Config[MyCustomClaims]{
		Store:      mockStore,
		SecretKey:  "super-secret-key-for-testing",
		Issuer:     "libauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	issuertest.IssuerVerifierContractTesting[MyCustomClaims](t, svc, svc, MyCustomClaims{Plan: "pro", IsAdmin: true})
}

func TestJWTIssuerVerifier_EdgeCases(t *testing.T) {
	ctx := context.Background()
	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error {
			return nil
		},
	}

	cfg := jwt.Config[MyCustomClaims]{
		Store:      mockStore,
		SecretKey:  "secret",
		Issuer:     "test",
		AccessTTL:  -1 * time.Minute, // Expired immediately
		RefreshTTL: 24 * time.Hour,
	}
	svc := jwt.New[MyCustomClaims](cfg)

	t.Run("Expired token returns ErrTokenExpired", func(t *testing.T) {
		claims := tokens.Claims[MyCustomClaims]{
			Subject: uuid.New(),
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)

		_, err = svc.VerifyAccessToken(ctx, pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrTokenExpired)
	})

	t.Run("Invalid signature returns ErrInvalidToken", func(t *testing.T) {
		// Create a token with a different secret
		otherSvc := jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
			Store:     mockStore,
			SecretKey: "different-secret",
			AccessTTL: 1 * time.Hour,
		})

		pair, err := otherSvc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.New()})
		require.NoError(t, err)

		_, err = svc.VerifyAccessToken(ctx, pair.AccessToken)
		assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
}
