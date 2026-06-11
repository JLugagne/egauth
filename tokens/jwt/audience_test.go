package jwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedKeyService builds a Service that signs/verifies with a single shared HS256 key but
// scopes itself to a given issuer and set of expected audiences. Two such services sharing the
// key model two distinct services sitting behind one symmetric secret.
// InsecureAllowWeakKey is set so callers may pass test-only secrets of any length.
func sharedKeyService(t *testing.T, secret, issuer string, expectedAud []string) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:                memory.NewStore[struct{}](),
		SecretKey:            secret,
		Issuer:               issuer,
		ExpectedAudience:     expectedAud,
		AccessTTL:            5 * time.Minute,
		RefreshTTL:           24 * time.Hour,
		InsecureAllowWeakKey: true,
	})
}

func mintAccess(t *testing.T, svc *jwt.Service[struct{}], audiences []string) string {
	t.Helper()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:   uuid.New(),
		TenantID:  "tenant-a",
		Audiences: audiences,
	})
	require.NoError(t, err)
	return pair.AccessToken
}

func TestVerifyAccessToken_RejectsForeignIssuer(t *testing.T) {
	const secret = "shared-symmetric-secret-key-abc"
	svcA := sharedKeyService(t, secret, "service-a", nil)
	svcB := sharedKeyService(t, secret, "service-b", nil)

	tok := mintAccess(t, svcA, nil)

	_, err := svcB.VerifyAccessTokenForTenant(context.Background(), "tenant-a", tok)
	require.Error(t, err)
	assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	assert.NotErrorIs(t, err, tokens.ErrTokenExpired)
}

func TestVerifyAccessToken_RejectsForeignAudience(t *testing.T) {
	const secret = "shared-symmetric-secret-key-abc"
	svcA := sharedKeyService(t, secret, "", []string{"aud-a"})
	svcB := sharedKeyService(t, secret, "", []string{"aud-b"})

	tok := mintAccess(t, svcA, []string{"aud-a"})

	_, err := svcB.VerifyAccessTokenForTenant(context.Background(), "tenant-a", tok)
	require.Error(t, err)
	assert.ErrorIs(t, err, tokens.ErrInvalidToken)
	assert.NotErrorIs(t, err, tokens.ErrTokenExpired)
}

func TestVerifyAccessToken_AcceptsOwnIssuerAndAudience(t *testing.T) {
	const secret = "shared-symmetric-secret-key-abc"
	svcA := sharedKeyService(t, secret, "service-a", []string{"aud-a"})

	tok := mintAccess(t, svcA, []string{"aud-a"})

	claims, err := svcA.VerifyAccessTokenForTenant(context.Background(), "tenant-a", tok)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Contains(t, claims.Audiences, "aud-a")
}

func TestVerifyAccessToken_AnyOfExpectedAudienceMatches(t *testing.T) {
	const secret = "shared-symmetric-secret-key-abc"
	// Verifier accepts a token carrying ANY of several configured audiences.
	verifier := sharedKeyService(t, secret, "", []string{"aud-x", "aud-y", "aud-z"})
	issuer := sharedKeyService(t, secret, "", nil)

	tok := mintAccess(t, issuer, []string{"aud-y"})

	claims, err := verifier.VerifyAccessTokenForTenant(context.Background(), "tenant-a", tok)
	require.NoError(t, err)
	require.NotNil(t, claims)
}

func TestVerifyAccessToken_BackwardCompatNoIssuerNoAudience(t *testing.T) {
	const secret = "shared-symmetric-secret-key-abc"
	// Issuer-less, audience-less verifier must accept any token (legacy behavior).
	issuer := sharedKeyService(t, secret, "some-issuer", nil)
	verifier := sharedKeyService(t, secret, "", nil)

	tok := mintAccess(t, issuer, []string{"whatever"})

	claims, err := verifier.VerifyAccessTokenForTenant(context.Background(), "tenant-a", tok)
	require.NoError(t, err)
	require.NotNil(t, claims)
}

func TestVerifyAccessToken_ExpiredStillReportsExpired(t *testing.T) {
	// Ensure the new iss/aud gating does not mask the expired sentinel.
	const secret = "shared-symmetric-secret-key-abc"
	store := memory.NewStore[struct{}]()
	now := time.Now()
	clock := now
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:                store,
		SecretKey:            secret,
		Issuer:               "service-a",
		AccessTTL:            time.Minute,
		Clock:                func() time.Time { return clock },
		InsecureAllowWeakKey: true,
	})
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:  uuid.New(),
		TenantID: "t",
	})
	require.NoError(t, err)

	clock = now.Add(2 * time.Minute)
	_, err = svc.VerifyAccessTokenForTenant(context.Background(), "t", pair.AccessToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, tokens.ErrTokenExpired))
}
