package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rememberService(t *testing.T, providerRemember bool) *jwt.Service[MyCustomClaims] {
	t.Helper()
	return jwt.New[MyCustomClaims](jwt.Config[MyCustomClaims]{
		Store:      memory.NewStore[MyCustomClaims](),
		SecretKey:  "super-secret-key-for-testing----",
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[MyCustomClaims](func(_ context.Context, userID uuid.UUID, tenant string) (tokens.Claims[MyCustomClaims], error) {
			return tokens.Claims[MyCustomClaims]{Subject: userID, TenantID: tenant, RememberMe: providerRemember}, nil
		}),
	})
}

func TestRememberMe_RoundTripsThroughAccessToken(t *testing.T) {
	ctx := context.Background()
	svc := rememberService(t, false)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.Must(uuid.NewV7()), RememberMe: true})
	require.NoError(t, err)
	assert.True(t, pair.Claims.RememberMe)

	verified, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)
	assert.True(t, verified.RememberMe)
	assert.Equal(t, true, decodeAccessPayload(t, pair.AccessToken)["remember_me"])

	plain, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	_, present := decodeAccessPayload(t, plain.AccessToken)["remember_me"]
	assert.False(t, present, "remember_me must be omitted when false")
}

func TestRememberMe_FamilyChoiceSurvivesRotation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		loginRemember    bool
		providerRemember bool
	}{
		{name: "remembered family stays remembered", loginRemember: true, providerRemember: false},
		{name: "provider cannot upgrade a session family", loginRemember: false, providerRemember: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc := rememberService(t, tc.providerRemember)

			pair, err := svc.IssueTokenPair(ctx, tokens.Claims[MyCustomClaims]{Subject: uuid.Must(uuid.NewV7()), RememberMe: tc.loginRemember})
			require.NoError(t, err)

			for range 3 {
				pair, err = svc.Rotate(ctx, "", pair.RefreshToken)
				require.NoError(t, err)
				assert.Equal(t, tc.loginRemember, pair.Claims.RememberMe)
			}
		})
	}
}
