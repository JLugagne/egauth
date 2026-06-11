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

// Tests for the injectable clock seam (N3): the JWT issuer's access-token TTL stamp AND the
// verify path's exp/nbf validation must both run off the injected clock. The verify path is
// the subtle half: golang-jwt validates exp against its OWN clock unless WithTimeFunc is
// wired, so a test that freezes the clock far from wall time is what proves both clocks share
// one source.

func TestWithClock_DeterministicTokenExpiry(t *testing.T) {
	ctx := context.Background()

	// A frozen clock far from real wall time, advanceable by hand.
	base := time.Date(2035, 6, 1, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "clock-secret-aaaaaaaaaaaaaaaaaaaaaaaa",
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     time.Hour,
		ClaimsProvider: okProvider(t),
		Clock:          clock,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)
	// The TTL stamp must come from the injected clock.
	assert.Equal(t, base.Add(5*time.Minute), pair.AccessTokenExpiresAt, "access exp must be clock-now + AccessTTL")

	// Verify under the SAME frozen clock: a token whose iat/exp are in 2035 would be rejected
	// by golang-jwt's real-wall-clock validator unless WithTimeFunc(clock) is wired into the
	// parser. Success here proves the verify path honors the injected clock.
	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err, "token must validate under the injected clock")
	assert.Equal(t, pair.AccessTokenExpiresAt.Unix(), claims.ExpiresAt.Unix())

	// Just before expiry: still valid.
	now = base.Add(5*time.Minute - time.Second)
	_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)

	// Past expiry: the verify path must report expiry deterministically.
	now = base.Add(5*time.Minute + time.Second)
	_, err = svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	assert.ErrorIs(t, err, tokens.ErrTokenExpired, "expired token must fail verification under the injected clock")
}
