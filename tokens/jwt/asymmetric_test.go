package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cryptoRand returns the crypto/rand reader; a tiny indirection so call sites read clearly.
func cryptoRand() io.Reader { return rand.Reader }

// handSignHS256 builds and signs a JWT with HS256 and the given secret, optionally stamping a kid.
// It is used to forge tokens for the alg-confusion and legacy-key tests.
func handSignHS256(t *testing.T, claims gojwt.MapClaims, kid string, secret []byte) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(secret)
	require.NoError(t, err)
	return signed
}

func ecdsaSignerForTest(t *testing.T, kid string, curve elliptic.Curve) jwt.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	sg, err := jwt.NewECDSASigner(kid, key)
	require.NoError(t, err)
	return sg
}

func eddsaSignerForTest(t *testing.T, kid string) jwt.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sg, err := jwt.NewEdDSASigner(kid, priv)
	require.NoError(t, err)
	return sg
}

func roundTripWith(t *testing.T, sg jwt.Signer, expectedAlg string) {
	ctx := context.Background()
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	userID := uuid.Must(uuid.NewV7())
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID, TenantID: ""})
	require.NoError(t, err)
	assert.Equal(t, sg.KeyID(), kidOf(t, pair.AccessToken))
	assert.Equal(t, expectedAlg, algOf(t, pair.AccessToken))

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)
}

// algOf returns the "alg" header of a JWT without verifying it.
func algOf(t *testing.T, tokenStr string) string {
	t.Helper()
	tok, _, err := gojwt.NewParser().ParseUnverified(tokenStr, gojwt.MapClaims{})
	require.NoError(t, err)
	alg, _ := tok.Header["alg"].(string)
	return alg
}

func TestAsymmetric_RS256_SignVerify(t *testing.T) {
	sg, _ := rsaSignerForTest(t, "rsa-1")
	roundTripWith(t, sg, "RS256")
}

func TestAsymmetric_ES256_SignVerify(t *testing.T) {
	roundTripWith(t, ecdsaSignerForTest(t, "ec-1", elliptic.P256()), "ES256")
}

func TestAsymmetric_EdDSA_SignVerify(t *testing.T) {
	roundTripWith(t, eddsaSignerForTest(t, "ed-1"), "EdDSA")
}

func TestAsymmetric_RotateRefreshKeepsAlg(t *testing.T) {
	ctx := context.Background()
	sg, _ := rsaSignerForTest(t, "rsa-1")
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	userID := uuid.Must(uuid.NewV7())
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)

	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "RS256", algOf(t, rotated.AccessToken))
	assert.Equal(t, "rsa-1", kidOf(t, rotated.AccessToken))

	_, err = svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
}
