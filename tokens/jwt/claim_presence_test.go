package jwt_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyAccessToken_RejectsTokenWithoutExpiry covers the claim-presence contract. A bearer
// token with no exp would otherwise be accepted as valid forever, and the claims mapping
// dereferences the timestamp — so an absent claim was both a permanent credential and a nil
// dereference on the verification path.
func TestVerifyAccessToken_RejectsTokenWithoutExpiry(t *testing.T) {
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "claim-presence-secret-aaaaaaaaaaaa",
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
	uid := uuid.Must(uuid.NewV7())

	for _, tc := range []struct {
		name string
		body string
	}{
		{"no exp, no iat", `{"sub":"` + uid.String() + `","iss":"egauth-test"}`},
		{"iat but no exp", `{"sub":"` + uid.String() + `","iss":"egauth-test","iat":1700000000}`},
		{"exp but no iat", `{"sub":"` + uid.String() + `","iss":"egauth-test","exp":4102444800}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() {
				_, err = svc.VerifyAccessTokenForTenant(context.Background(), "", unsignedToken(tc.body))
			}, "a token missing exp/iat must be rejected, never panic the verification path")
			require.Error(t, err)
			assert.ErrorIs(t, err, tokens.ErrInvalidToken,
				"an absent or unusable claim is an invalid-token condition")
		})
	}
}

// TestVerifyAccessToken_AcceptsATokenWithBothTimestamps is the control: the stricter requirements
// must not reject a normally minted token.
func TestVerifyAccessToken_AcceptsATokenWithBothTimestamps(t *testing.T) {
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "claim-presence-secret-aaaaaaaaaaaa",
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
	})
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(context.Background(), "", pair.AccessToken)
	require.NoError(t, err)
	assert.False(t, claims.IssuedAt.IsZero(), "a minted token carries iat")
	assert.False(t, claims.ExpiresAt.IsZero(), "a minted token carries exp")
}

// unsignedToken builds a JWT-shaped string with the given JSON payload and a placeholder signature.
// It only needs to reach the claim-presence checks, which run on the parsed claims.
func unsignedToken(payload string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256","typ":"JWT","kid":"k1"}`) + "." + enc(payload) + "." + enc("sig")
}
