package jwt_test

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaSignerForTest builds an RS256 jwt.Signer with a fresh 2048-bit key.
func rsaSignerForTest(t *testing.T, kid string) (jwt.Signer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(cryptoRand(), 2048)
	require.NoError(t, err)
	sg, err := jwt.NewRSASigner(kid, key)
	require.NoError(t, err)
	return sg, key
}

func signersService(t *testing.T, cfg jwt.Config[struct{}]) *jwt.Service[struct{}] {
	t.Helper()
	cfg.Store = memory.NewStore[struct{}]()
	cfg.Issuer = "egauth-test"
	cfg.AccessTTL = 5 * time.Minute
	cfg.RefreshTTL = 24 * time.Hour
	cfg.ClaimsProvider = okProvider(t)
	return jwt.New[struct{}](cfg)
}

func TestConfig_SignersSupersedeStatic(t *testing.T) {
	ctx := context.Background()
	sg, _ := rsaSignerForTest(t, "rsa-1")
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	assert.Equal(t, "rsa-1", kidOf(t, pair.AccessToken))

	_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)
}

func TestConfig_SignersWithLegacySecretKey(t *testing.T) {
	ctx := context.Background()
	const legacySecret = "legacy-signing-secret-aaaaaaaaaaaa" // >= 32 bytes
	sg, _ := rsaSignerForTest(t, "rsa-1")
	svc := signersService(t, jwt.Config[struct{}]{
		Signers:   []jwt.Signer{sg},
		SecretKey: legacySecret,
	})

	// A Signers-kid token verifies.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)

	// A kid-less HS256 token hand-signed with the legacy SecretKey verifies (verify-only legacy).
	legacyTok := handSignHS256(t, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}, "", []byte(legacySecret))
	_, err = svc.VerifyAccessTokenForTenant(ctx, "", legacyTok)
	require.NoError(t, err, "kid-less legacy HS256 token must verify against SecretKey")
}

func TestConfig_SignersRejectSigningKeysCombo(t *testing.T) {
	sg, _ := rsaSignerForTest(t, "rsa-1")
	cfg := jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		Signers:        []jwt.Signer{sg},
		SigningKeys:    []jwt.SigningKey{{KeyID: "k1", Secret: oldSecret}},
	}
	require.Error(t, cfg.Validate())

	assert.Panics(t, func() { jwt.New[struct{}](cfg) })
}

func TestConfig_SignersRequireActiveKeyIDWhenMultiple(t *testing.T) {
	sg1, _ := rsaSignerForTest(t, "rsa-1")
	sg2, _ := rsaSignerForTest(t, "rsa-2")
	base := jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		Signers:        []jwt.Signer{sg1, sg2},
	}
	require.Error(t, base.Validate(), "two signers without ActiveKeyID must fail validation")
	assert.Panics(t, func() { jwt.New[struct{}](base) })

	withActive := base
	withActive.ActiveKeyID = "rsa-2"
	require.NoError(t, withActive.Validate())
	assert.NotPanics(t, func() { jwt.New[struct{}](withActive) })
}

func TestConfig_SignersUniqueNonEmptyKeyID(t *testing.T) {
	dup1, _ := rsaSignerForTest(t, "dup")
	dup2, _ := rsaSignerForTest(t, "dup")
	dupCfg := jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		Signers:        []jwt.Signer{dup1, dup2},
	}
	require.Error(t, dupCfg.Validate(), "duplicate Signers KeyID must fail validation")

	// An empty KeyID inside a Signers set: an HMAC signer may legally have an empty key id,
	// but it must not be placed in a Signers set.
	emptyKid, err := jwt.NewHMACSigner("", make([]byte, jwt.MinSecretKeyLength))
	require.NoError(t, err)
	emptyCfg := jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		Signers:        []jwt.Signer{emptyKid},
	}
	require.Error(t, emptyCfg.Validate(), "empty KeyID in a Signers set must fail validation")
	assert.Panics(t, func() { jwt.New[struct{}](emptyCfg) })
}
