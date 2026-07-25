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

// TestRotate_SupersededRetentionShortensTheConsumedWindow proves the opt-in GC knob: with
// SupersededRefreshRetention set, the row of a token that has just been rotated away keeps only a
// short retained window (so the reaper can collect it) instead of its full RefreshTTL, while
// replay detection inside that window still works.
func TestRotate_SupersededRetentionShortensTheConsumedWindow(t *testing.T) {
	ctx := context.Background()
	now := familyCapBase
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:                      store,
		SecretKey:                  "retention-secret-aaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:                     "egauth-test",
		AccessTTL:                  5 * time.Minute,
		RefreshTTL:                 24 * time.Hour,
		ClaimsProvider:             okProvider(t),
		Clock:                      func() time.Time { return now },
		ReuseGracePeriod:           10 * time.Second,
		SupersededRefreshRetention: time.Minute,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	parentHash := tokens.HashToken(pair.RefreshToken)

	stored, err := store.FindRefreshToken(ctx, "", parentHash)
	require.NoError(t, err)
	require.Equal(t, familyCapBase.Add(24*time.Hour), stored.ExpiresAt)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	superseded, err := store.FindRefreshToken(ctx, "", parentHash)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Minute), superseded.ExpiresAt,
		"a superseded row must be retained only for the configured window, not its full RefreshTTL")
	require.NotNil(t, superseded.ConsumedAt, "the row must stay marked consumed so replay is still detected")

	// Replay inside the retained window is still caught as reuse (theft detection preserved).
	now = now.Add(30 * time.Second)
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrRefreshTokenReused,
		"replay of the superseded token inside the retained window must still be detected")
}

// TestRotate_SupersededRetentionOffByDefault pins the default: nothing is shortened, so the
// after-grace theft signal keeps its full window unless an operator opts into the trade-off.
func TestRotate_SupersededRetentionOffByDefault(t *testing.T) {
	ctx := context.Background()
	now := familyCapBase
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "retention-secret-aaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		Clock:          func() time.Time { return now },
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	parentHash := tokens.HashToken(pair.RefreshToken)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	superseded, err := store.FindRefreshToken(ctx, "", parentHash)
	require.NoError(t, err)
	assert.Equal(t, familyCapBase.Add(24*time.Hour), superseded.ExpiresAt,
		"by default a superseded row keeps its original retained window")
}

// TestRotate_SupersededRetentionNeverBelowReuseGrace pins the fail-safe normalisation: a retention
// shorter than the reuse-grace window would blind the benign-concurrency allowance, so it is
// raised to the grace period.
func TestRotate_SupersededRetentionNeverBelowReuseGrace(t *testing.T) {
	ctx := context.Background()
	now := familyCapBase
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:                      store,
		SecretKey:                  "retention-secret-aaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:                     "egauth-test",
		AccessTTL:                  5 * time.Minute,
		RefreshTTL:                 24 * time.Hour,
		ClaimsProvider:             okProvider(t),
		Clock:                      func() time.Time { return now },
		ReuseGracePeriod:           time.Minute,
		SupersededRefreshRetention: time.Second,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	parentHash := tokens.HashToken(pair.RefreshToken)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	superseded, err := store.FindRefreshToken(ctx, "", parentHash)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Minute), superseded.ExpiresAt,
		"a retention below the reuse grace must be raised to the grace period")
}
