package jwt_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func okProvider(t *testing.T) tokens.ClaimsProviderFunc[struct{}] {
	return func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		// Leave ExpiresAt zero so the issuer's configured access TTL applies.
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
	}
}

func newRotatingService(t *testing.T, provider tokens.ClaimsProvider[struct{}], refreshTTL time.Duration) (*jwt.Service[struct{}], *memory.Store[struct{}]) {
	t.Helper()
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "rotation-secret",
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     refreshTTL,
		ClaimsProvider: provider,
	})
	return svc, store
}

func TestRotate_HappyPath(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	userID := uuid.New()
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)

	assert.NotEqual(t, pair.RefreshToken, newPair.RefreshToken, "refresh token must change on rotation")
	assert.NotEqual(t, pair.AccessToken, newPair.AccessToken, "access token must change on rotation")
	assert.Equal(t, userID, newPair.Claims.Subject, "subject preserved via claims provider")

	// The rotated token must verify and the new access token must be valid.
	claims, err := svc.VerifyAccessToken(ctx, newPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)
}

func TestRotate_ReuseDetectionRevokesFamily(t *testing.T) {
	ctx := context.Background()
	// Strict mode (negative grace): any replay of a consumed token is treated as theft.
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            store,
		SecretKey:        "rotation-secret",
		Issuer:           "egauth-test",
		AccessTTL:        5 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ClaimsProvider:   okProvider(t),
		ReuseGracePeriod: -1, // strict: no benign-concurrency leeway
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// Legitimate rotation: A -> B.
	newPair, err := svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)

	// Replay the already-consumed A: must be detected as reuse.
	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

	// Reuse must have revoked the WHOLE family, so the legitimate descendant B is dead too.
	_, err = svc.Rotate(ctx, newPair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "family revocation must invalidate descendant tokens")
}

func TestRotate_ReuseWithinGraceKeepsFamily(t *testing.T) {
	ctx := context.Background()
	// Default grace (10s): an immediate replay is benign concurrency, not theft.
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)

	// Immediate replay of the consumed ancestor: rejected, but within grace so the family
	// must survive.
	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

	_, err = svc.Rotate(ctx, newPair.RefreshToken)
	require.NoError(t, err, "within the grace window the descendant must survive a benign replay")
}

func TestRotate_ExpiredRefresh(t *testing.T) {
	ctx := context.Background()
	// Negative TTL => the issued refresh token is already expired.
	svc, _ := newRotatingService(t, okProvider(t), -time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrTokenExpired)
}

func TestRotate_NotFound(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), time.Hour)

	_, err := svc.Rotate(ctx, "a-token-that-was-never-issued")
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
}

func TestRotate_NoClaimsProvider(t *testing.T) {
	ctx := context.Background()
	// Build a service WITHOUT a ClaimsProvider.
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "s",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrNoClaimsProvider)

	// The guard must trip BEFORE consuming, so the token is still usable once a provider
	// is available — verify it has not been consumed.
	rt, err := store.FindRefreshToken(ctx, tokens.HashToken(pair.RefreshToken))
	require.NoError(t, err)
	assert.Nil(t, rt.ConsumedAt, "token must not be consumed when rotation is unavailable")
}

func TestRotate_ClaimsProviderErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	disabled := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{}, errors.New("user disabled")
	})
	svc, _ := newRotatingService(t, disabled, time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.Error(t, err, "rotation must fail when fresh claims cannot be resolved")

	// Fail-closed: the token was consumed, so a retry is treated as reuse (no new pair leaks).
	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)
}

func TestRotate_MultiTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New(), TenantID: "t1"})
	require.NoError(t, err)

	// Rotating under the wrong tenant must not find the token.
	_, err = svc.Rotate(ctx, pair.RefreshToken, tokens.WithTenant("t2"))
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

	// Rotating under the correct tenant succeeds and preserves the tenant.
	newPair, err := svc.Rotate(ctx, pair.RefreshToken, tokens.WithTenant("t1"))
	require.NoError(t, err)
	assert.Equal(t, "t1", newPair.Claims.TenantID)
}

func TestRotate_ConcurrentBenignKeepsFamily(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	const n = 8
	results := make(chan *tokens.TokenPair[struct{}], n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			np, err := svc.Rotate(ctx, pair.RefreshToken)
			if err != nil {
				results <- nil
				return
			}
			results <- np
		}()
	}
	wg.Wait()
	close(results)

	var winner *tokens.TokenPair[struct{}]
	for r := range results {
		if r != nil {
			require.Nil(t, winner, "only one concurrent rotation of the same token may succeed")
			winner = r
		}
	}
	require.NotNil(t, winner, "exactly one concurrent rotation should succeed")

	// Benign concurrency (same token raced) must NOT be treated as theft: the family must
	// survive, so the winner's freshly-issued token still rotates.
	_, err = svc.Rotate(ctx, winner.RefreshToken)
	require.NoError(t, err, "family must survive benign concurrent rotation of the same token")
}

func TestRotate_ProviderTenantCannotRelocateFamily(t *testing.T) {
	ctx := context.Background()
	// A provider that ignores the tenant hint (returns "") must NOT orphan the descendant
	// into a different partition than the one the family is found/revoked under.
	provider := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: userID}, nil // TenantID deliberately empty
	})
	svc, _ := newRotatingService(t, provider, 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New(), TenantID: "t1"})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, pair.RefreshToken, tokens.WithTenant("t1"))
	require.NoError(t, err)
	assert.Equal(t, "t1", newPair.Claims.TenantID, "descendant must stay in the family tenant")

	// The descendant must remain reachable (and therefore revocable) under the family
	// tenant — proving it was not orphaned into tenant "".
	next, err := svc.Rotate(ctx, newPair.RefreshToken, tokens.WithTenant("t1"))
	require.NoError(t, err, "descendant must live in the family tenant, not be orphaned")
	assert.Equal(t, "t1", next.Claims.TenantID)
}

func TestRotate_AccessTTLNotExtendedByProvider(t *testing.T) {
	ctx := context.Background()
	// A provider that returns a far-future ExpiresAt must not extend the access-token life:
	// the access TTL is issuer-controlled on refresh.
	provider := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID, ExpiresAt: time.Now().Add(1000 * time.Hour)}, nil
	})
	svc, _ := newRotatingService(t, provider, 24*time.Hour) // AccessTTL is 5m (see helper)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), newPair.AccessTokenExpiresAt, time.Minute,
		"rotated access token must use the issuer's AccessTTL, not the provider-supplied expiry")
}

func TestRotate_ConcurrentSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	const n = 16
	var success int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := svc.Rotate(ctx, pair.RefreshToken); err == nil {
				atomic.AddInt32(&success, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&success), "exactly one concurrent rotation of the same token may succeed")
}
