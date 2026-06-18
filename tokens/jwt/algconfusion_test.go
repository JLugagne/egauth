package jwt_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// rsaPublicAsHMACSecret returns the DER-encoded RSA public key bytes, the classic payload an
// attacker feeds to HMAC-verify in an RS256->HS256 confusion attack (the verifier's "public" key
// becomes the attacker's shared HMAC secret).
func rsaPublicAsHMACSecret(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return der
}

func TestAlgConfusion_RS256TokenPresentedAsHS256(t *testing.T) {
	ctx := context.Background()
	sg, key := rsaSignerForTest(t, "k1")
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	// Forge an HS256 token whose kid maps to the RSA verifier, HMAC-signed with the RSA public DER.
	forged := handSignHS256(t, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, "k1", rsaPublicAsHMACSecret(t, &key.PublicKey))

	_, err := svc.VerifyAccessTokenForTenant(ctx, "", forged)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrInvalidToken), "RS256->HS256 confusion must be rejected, got %v", err)
}

func TestAlgConfusion_HS256TokenPresentedAsRS256(t *testing.T) {
	ctx := context.Background()
	const secret = "hmac-confusion-secret-aaaaaaaaaaaa" // >= 32 bytes
	hsSigner, err := jwt.NewHMACSigner("k1", []byte(secret))
	require.NoError(t, err)
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{hsSigner}})

	// Forge an RS256-claimed token with kid k1 (which maps to an HMAC signer). Sign with a real
	// RSA key so the token is structurally a valid RS256 token; the alg pin must still reject it.
	_, key := rsaSignerForTest(t, "ignored")
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	forged, err := tok.SignedString(key)
	require.NoError(t, err)

	_, err = svc.VerifyAccessTokenForTenant(ctx, "", forged)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrInvalidToken), "HS256<-RS256 confusion must be rejected, got %v", err)
}

func TestAlgConfusion_NoneRejected(t *testing.T) {
	ctx := context.Background()
	sg, _ := rsaSignerForTest(t, "k1")
	svc := signersService(t, jwt.Config[struct{}]{Signers: []jwt.Signer{sg}})

	tok := gojwt.NewWithClaims(gojwt.SigningMethodNone, gojwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"iss": "egauth-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	forged, err := tok.SignedString(gojwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = svc.VerifyAccessTokenForTenant(ctx, "", forged)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrInvalidToken), "alg:none must be rejected, got %v", err)
}

// fixedKeyStore is a minimal jwt.KeyStore returning one signer per tenant — enough to exercise the
// KeyStore-backed tenantKeyFunc verify path.
type fixedKeyStore struct {
	byTenant map[string]jwt.Signer
}

func (s *fixedKeyStore) ActiveSigningKey(_ context.Context, tenantID string) (jwt.Signer, error) {
	sg, ok := s.byTenant[tenantID]
	if !ok {
		return nil, errors.New("no key for tenant")
	}
	return sg, nil
}

func (s *fixedKeyStore) VerificationKeys(_ context.Context, tenantID string) (map[string]jwt.Signer, error) {
	sg, ok := s.byTenant[tenantID]
	if !ok {
		return nil, errors.New("no key for tenant")
	}
	return map[string]jwt.Signer{sg.KeyID(): sg}, nil
}

func TestAlgConfusion_TenantKeyFunc(t *testing.T) {
	ctx := context.Background()
	sg, key := rsaSignerForTest(t, "tk1")
	ks := &fixedKeyStore{byTenant: map[string]jwt.Signer{"acme": sg}}

	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		SecretKey:      "static-single-tenant-key-at-least-32b!",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		KeyStore:       ks,
	})

	// Sanity: a legitimately issued RS256 token for "acme" verifies.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), TenantID: "acme"})
	require.NoError(t, err)
	_, err = svc.VerifyAccessTokenForTenant(ctx, "acme", pair.AccessToken)
	require.NoError(t, err)

	// Forge an HS256 token with the tenant's kid, HMAC-signed with the RSA public DER.
	forged := handSignHS256(t, gojwt.MapClaims{
		"sub":       uuid.Must(uuid.NewV7()).String(),
		"iss":       "egauth-test",
		"tenant_id": "acme",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}, "tk1", rsaPublicAsHMACSecret(t, &key.PublicKey))

	_, err = svc.VerifyAccessTokenForTenant(ctx, "acme", forged)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrInvalidToken), "RS256->HS256 confusion through KeyStore must be rejected, got %v", err)
}
