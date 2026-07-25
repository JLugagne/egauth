package jwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const numericDateSecret = "numeric-date-secret-aaaaaaaaaaaaaaa"

func numericDateService(t *testing.T) *jwt.Service[struct{}] {
	t.Helper()
	sg, err := jwt.NewHMACSigner("k1", []byte(numericDateSecret))
	require.NoError(t, err)
	return signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})
}

func TestVerifyAccessToken_MissingExpirationIsRejected(t *testing.T) {
	ctx := context.Background()
	svc := numericDateService(t)

	forged := handSignHS256(t, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"iat": time.Now().Unix(),
	}, "k1", []byte(numericDateSecret))

	_, err := svc.VerifyAccessTokenForTenant(ctx, "", forged)
	require.Error(t, err, "a validly signed token with no exp must be rejected, never panic")
	require.True(t, errors.Is(err, tokens.ErrInvalidClaims), "want ErrInvalidClaims, got %v", err)
}

func TestVerifyAccessToken_MissingIssuedAtIsRejected(t *testing.T) {
	ctx := context.Background()
	svc := numericDateService(t)

	forged := handSignHS256(t, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, "k1", []byte(numericDateSecret))

	_, err := svc.VerifyAccessTokenForTenant(ctx, "", forged)
	require.Error(t, err, "a validly signed token with no iat must be rejected, never panic")
	require.True(t, errors.Is(err, tokens.ErrInvalidClaims), "want ErrInvalidClaims, got %v", err)
}
