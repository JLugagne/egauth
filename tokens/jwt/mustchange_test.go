package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeAccessPayload returns the decoded JSON payload (claims segment) of a JWT as a
// generic map so a test can assert on raw claim keys, including their presence/absence.
func decodeAccessPayload(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "access token must have three segments")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))
	return payload
}

func mustChangeService(t *testing.T) *jwt.Service[MyCustomClaims] {
	t.Helper()
	mockStore := &storetest.MockStore[MyCustomClaims]{
		SaveRefreshTokenFunc: func(_ context.Context, _ string, _ *tokens.RefreshToken) error {
			return nil
		},
	}
	cfg := jwt.Config[MyCustomClaims]{
		Store:      mockStore,
		SecretKey:  "super-secret-key-for-testing----", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
	return jwt.New[MyCustomClaims](cfg)
}

// TestMustChangePassword_RoundTrip verifies the first-class must-change claim survives a
// sign->verify round-trip alongside a non-empty custom claims type C, and that it is omitted
// from the JWT payload (omitempty) when false.
func TestMustChangePassword_RoundTrip(t *testing.T) {
	ctx := context.Background()
	svc := mustChangeService(t)

	t.Run("flag set survives issue and verify", func(t *testing.T) {
		claims := tokens.Claims[MyCustomClaims]{
			Subject:            uuid.Must(uuid.NewV7()),
			MustChangePassword: true,
			Custom:             MyCustomClaims{Plan: "pro", IsAdmin: true},
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)
		assert.True(t, pair.Claims.MustChangePassword, "issued claims should echo the flag")

		verified, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		require.NoError(t, err)
		assert.True(t, verified.MustChangePassword, "verified claims should carry the flag")
		// The custom claims must still round-trip unaffected by the new field.
		assert.Equal(t, MyCustomClaims{Plan: "pro", IsAdmin: true}, verified.Custom)

		payload := decodeAccessPayload(t, pair.AccessToken)
		assert.Equal(t, true, payload["must_change_password"], "claim should be present in JSON when true")
	})

	t.Run("flag false is omitted from JSON", func(t *testing.T) {
		claims := tokens.Claims[MyCustomClaims]{
			Subject:            uuid.Must(uuid.NewV7()),
			MustChangePassword: false,
			Custom:             MyCustomClaims{Plan: "free"},
		}

		pair, err := svc.IssueTokenPair(ctx, claims)
		require.NoError(t, err)

		payload := decodeAccessPayload(t, pair.AccessToken)
		_, present := payload["must_change_password"]
		assert.False(t, present, "claim must be omitted from JSON when false (omitempty)")

		verified, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
		require.NoError(t, err)
		assert.False(t, verified.MustChangePassword, "absent claim verifies as false")
	})
}
