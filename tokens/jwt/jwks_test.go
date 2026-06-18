package jwt_test

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicJWKS_RSA(t *testing.T) {
	sg, key := rsaSignerForTest(t, "rsa-1")
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	set := svc.PublicJWKS()
	require.Len(t, set.Keys, 1)
	jwk := set.Keys[0]
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.Equal(t, "rsa-1", jwk.Kid)
	require.NotEmpty(t, jwk.N)
	require.NotEmpty(t, jwk.E)

	// JSON must not leak any private fields.
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "\"d\"")

	// Reconstruct the public key from n,e and compare to the signer's public key.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	require.NoError(t, err)
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	assert.Equal(t, 0, key.PublicKey.N.Cmp(n))
	assert.Equal(t, key.PublicKey.E, int(e.Int64()))
}

func TestPublicJWKS_EC(t *testing.T) {
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{ecdsaSignerForTest(t, "ec-1", elliptic.P256())}})
	set := svc.PublicJWKS()
	require.Len(t, set.Keys, 1)
	jwk := set.Keys[0]
	assert.Equal(t, "EC", jwk.Kty)
	assert.Equal(t, "P-256", jwk.Crv)
	assert.Equal(t, "ES256", jwk.Alg)

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	require.NoError(t, err)
	assert.Len(t, x, 32)
	assert.Len(t, y, 32)
}

func TestPublicJWKS_EdDSA(t *testing.T) {
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{eddsaSignerForTest(t, "ed-1")}})
	set := svc.PublicJWKS()
	require.Len(t, set.Keys, 1)
	jwk := set.Keys[0]
	assert.Equal(t, "OKP", jwk.Kty)
	assert.Equal(t, "Ed25519", jwk.Crv)
	assert.Equal(t, "EdDSA", jwk.Alg)
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)
	assert.Len(t, x, 32)
}

func TestPublicJWKS_HMAC_MetadataOnly(t *testing.T) {
	sg, err := jwt.NewHMACSigner("hs-1", []byte("hmac-jwks-secret-aaaaaaaaaaaaaaaa"))
	require.NoError(t, err)
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	set := svc.PublicJWKS()
	require.Len(t, set.Keys, 1)
	jwk := set.Keys[0]
	assert.Equal(t, "oct", jwk.Kty)
	assert.Equal(t, "hs-1", jwk.Kid)
	assert.Equal(t, "HS256", jwk.Alg)

	raw, err := json.Marshal(set)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(raw), "\"k\""), "HMAC secret must never be emitted")
}

func TestPublicJWKS_MixedSet(t *testing.T) {
	rsaSg, _ := rsaSignerForTest(t, "rsa-1")
	hsSg, err := jwt.NewHMACSigner("hs-1", []byte("hmac-jwks-secret-aaaaaaaaaaaaaaaa"))
	require.NoError(t, err)
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{rsaSg, hsSg}, ActiveKeyID: "rsa-1"})

	set := svc.PublicJWKS()
	require.Len(t, set.Keys, 2)
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(raw), "\"k\""), "oct entry must carry no secret")
}
