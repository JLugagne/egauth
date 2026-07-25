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
	"github.com/stretchr/testify/require"
)

// The reuse-grace decision must be taken with the INJECTED clock, not the process wall clock:
// consumed_at is written by whatever clock the store runs on, and the comparison against it is a
// theft-detection trigger. A frozen clock far from wall time is what separates the two sources.

const reuseGraceSecret = "reuse-grace-secret-aaaaaaaaaaaaaaa"

func reuseGraceService(t *testing.T, clock func() time.Time, grace time.Duration) (*jwt.Service[struct{}], *memory.Store[struct{}]) {
	t.Helper()
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            store,
		SecretKey:        reuseGraceSecret,
		Issuer:           "egauth-test",
		AccessTTL:        5 * time.Minute,
		RefreshTTL:       time.Hour,
		ClaimsProvider:   okProvider(t),
		Clock:            clock,
		ReuseGracePeriod: grace,
	})
	return svc, store
}

func TestRotate_ReuseGraceUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2035, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, store := reuseGraceService(t, func() time.Time { return base }, 10*time.Second)

	const plaintext = "already-consumed-refresh-token"
	consumedAt := base.Add(-time.Hour)
	family := uuid.Must(uuid.NewV7())
	require.NoError(t, store.SaveRefreshToken(ctx, "", &tokens.RefreshToken{
		Hash:       tokens.HashToken(plaintext),
		FamilyID:   family,
		UserID:     uuid.Must(uuid.NewV7()),
		ExpiresAt:  base.Add(time.Hour),
		CreatedAt:  base.Add(-2 * time.Hour),
		ConsumedAt: &consumedAt,
	}))

	_, err := svc.Rotate(ctx, "", plaintext)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrRefreshTokenReused),
		"a token consumed an hour before clock-now is well past the grace window: want theft handling, got %v", err)
	require.False(t, errors.Is(err, tokens.ErrRefreshConcurrent),
		"the wall clock must not be consulted: %v", err)
}

func TestRotate_ReuseGraceClampsStoreClockAhead(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2035, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, store := reuseGraceService(t, func() time.Time { return base }, 10*time.Second)

	const plaintext = "future-consumed-refresh-token"
	consumedAt := base.Add(time.Hour)
	require.NoError(t, store.SaveRefreshToken(ctx, "", &tokens.RefreshToken{
		Hash:       tokens.HashToken(plaintext),
		FamilyID:   uuid.Must(uuid.NewV7()),
		UserID:     uuid.Must(uuid.NewV7()),
		ExpiresAt:  base.Add(2 * time.Hour),
		CreatedAt:  base.Add(-time.Hour),
		ConsumedAt: &consumedAt,
	}))

	_, err := svc.Rotate(ctx, "", plaintext)
	require.Error(t, err)
	require.True(t, errors.Is(err, tokens.ErrRefreshConcurrent),
		"a consumed_at ahead of the app clock is store skew, not theft: want the concurrency sentinel, got %v", err)
}
