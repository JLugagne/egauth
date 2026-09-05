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
		SecretKey:      "rotation-secret-aaaaaaaaaaaaaaa!", // 32 bytes
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

	userID := uuid.Must(uuid.NewV7())
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	assert.NotEqual(t, pair.RefreshToken, newPair.RefreshToken, "refresh token must change on rotation")
	assert.NotEqual(t, pair.AccessToken, newPair.AccessToken, "access token must change on rotation")
	assert.Equal(t, userID, newPair.Claims.Subject, "subject preserved via claims provider")

	// The rotated token must verify and the new access token must be valid.
	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", newPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)
}

// TestRotate_CarriesMustChangePasswordForward proves the forced-password-change gate survives a
// silent refresh. A pair issued with MustChangePassword=true rotates to a token that STILL carries
// the flag — and stays flagged down the whole rotation chain — even though the ClaimsProvider
// returns UNFLAGGED claims (modelling a normal app provider that does not re-query the credential's
// must-change state). Rotate replays the flag verbatim from the parent refresh record, so a user
// cannot escape WithPasswordChangeGate by waiting for the access token to expire and refreshing.
// Conversely an unflagged family must never acquire the flag on refresh.
func TestRotate_CarriesMustChangePasswordForward(t *testing.T) {
	ctx := context.Background()
	// okProvider deliberately returns claims WITHOUT the flag — the carry-forward must come from
	// the stored refresh family, not from the provider.
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)
	userID := uuid.Must(uuid.NewV7())

	t.Run("flagged family stays flagged across the rotation chain", func(t *testing.T) {
		pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID, MustChangePassword: true})
		require.NoError(t, err)
		require.True(t, pair.Claims.MustChangePassword)

		newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
		require.NoError(t, err)
		claims, err := svc.VerifyAccessTokenForTenant(ctx, "", newPair.AccessToken)
		require.NoError(t, err)
		assert.True(t, claims.MustChangePassword,
			"the renewed token must still require a change (carried from the parent), not dropped by the provider")

		// A second refresh further down the chain must keep carrying it.
		newPair2, err := svc.Rotate(ctx, "", newPair.RefreshToken)
		require.NoError(t, err)
		claims2, err := svc.VerifyAccessTokenForTenant(ctx, "", newPair2.AccessToken)
		require.NoError(t, err)
		assert.True(t, claims2.MustChangePassword, "the flag must persist down the whole rotation chain")
	})

	t.Run("unflagged family stays unflagged across rotation", func(t *testing.T) {
		pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
		require.NoError(t, err)
		newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
		require.NoError(t, err)
		claims, err := svc.VerifyAccessTokenForTenant(ctx, "", newPair.AccessToken)
		require.NoError(t, err)
		assert.False(t, claims.MustChangePassword, "an unflagged family must never acquire the flag on refresh")
	})

	t.Run("unflagged family acquires flag when claims provider flags user", func(t *testing.T) {
		flaggingProvider := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, uid uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: uid, TenantID: tenantID, MustChangePassword: true}, nil
		})
		flaggingSvc, _ := newRotatingService(t, flaggingProvider, 24*time.Hour)

		pair, err := flaggingSvc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID, MustChangePassword: false})
		require.NoError(t, err)
		require.False(t, pair.Claims.MustChangePassword)

		newPair, err := flaggingSvc.Rotate(ctx, "", pair.RefreshToken)
		require.NoError(t, err)
		assert.True(t, newPair.Claims.MustChangePassword, "rotated pair claims must reflect MustChangePassword=true from claims provider")

		claims, err := flaggingSvc.VerifyAccessTokenForTenant(ctx, "", newPair.AccessToken)
		require.NoError(t, err)
		assert.True(t, claims.MustChangePassword, "verified access token claims must have MustChangePassword=true")
	})
}

func TestRotate_ReuseDetectionRevokesFamily(t *testing.T) {
	ctx := context.Background()
	// Strict mode (negative grace): any replay of a consumed token is treated as theft.
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            store,
		SecretKey:        "rotation-secret-aaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:           "egauth-test",
		AccessTTL:        5 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ClaimsProvider:   okProvider(t),
		ReuseGracePeriod: -1, // strict: no benign-concurrency leeway
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	// Legitimate rotation: A -> B.
	newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	// Replay the already-consumed A: must be detected as reuse.
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

	// Reuse must have revoked the WHOLE family, so the legitimate descendant B is dead too.
	_, err = svc.Rotate(ctx, "", newPair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound, "family revocation must invalidate descendant tokens")
}

func TestRotate_ReuseWithinGraceKeepsFamily(t *testing.T) {
	ctx := context.Background()
	// Default grace (10s): an immediate replay is benign concurrency, not theft.
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	// Immediate replay of the consumed ancestor: rejected, but within grace so the family
	// must survive.
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)

	_, err = svc.Rotate(ctx, "", newPair.RefreshToken)
	require.NoError(t, err, "within the grace window the descendant must survive a benign replay")
}

func TestRotate_ExpiredRefresh(t *testing.T) {
	ctx := context.Background()
	// Negative TTL => the issued refresh token is already expired.
	svc, _ := newRotatingService(t, okProvider(t), -time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrTokenExpired)
}

func TestRotate_NotFound(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), time.Hour)

	_, err := svc.Rotate(ctx, "", "a-token-that-was-never-issued")
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)
}

func TestRotate_NoClaimsProvider(t *testing.T) {
	ctx := context.Background()
	// Build a service WITHOUT a ClaimsProvider.
	// InsecureAllowWeakKey is set because the key length is not the subject of this test.
	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:                store,
		SecretKey:            "s",
		AccessTTL:            time.Minute,
		RefreshTTL:           time.Hour,
		InsecureAllowWeakKey: true,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrNoClaimsProvider)

	// The guard must trip BEFORE consuming, so the token is still usable once a provider
	// is available — verify it has not been consumed.
	rt, err := store.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.NoError(t, err)
	assert.Nil(t, rt.ConsumedAt, "token must not be consumed when rotation is unavailable")
}

func TestRotate_ClaimsProviderErrorDoesNotConsume(t *testing.T) {
	ctx := context.Background()
	disabled := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{}, errors.New("provider transient error")
	})
	svc, store := newRotatingService(t, disabled, time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.Error(t, err, "rotation must fail when fresh claims cannot be resolved")

	// The token must NOT be consumed, so a retry can succeed once the transient error clears.
	// This prevents dropping the user's session over a transient claims-provider failure.
	rt, err := store.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.NoError(t, err)
	assert.Nil(t, rt.ConsumedAt, "token must not be consumed when claims provider fails")
}

func TestRotate_MultiTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), TenantID: "t1"})
	require.NoError(t, err)

	// Rotating under the wrong tenant must not find the token.
	_, err = svc.Rotate(ctx, "t2", pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenNotFound)

	// Rotating under the correct tenant succeeds and preserves the tenant.
	newPair, err := svc.Rotate(ctx, "t1", pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "t1", newPair.Claims.TenantID)
}

func TestRotate_ConcurrentBenignKeepsFamily(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	const n = 8
	results := make(chan *tokens.TokenPair[struct{}], n)
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			np, err := svc.Rotate(ctx, "", pair.RefreshToken)
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
	_, err = svc.Rotate(ctx, "", winner.RefreshToken)
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

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), TenantID: "t1"})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, "t1", pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "t1", newPair.Claims.TenantID, "descendant must stay in the family tenant")

	// The descendant must remain reachable (and therefore revocable) under the family
	// tenant — proving it was not orphaned into tenant "".
	next, err := svc.Rotate(ctx, "t1", newPair.RefreshToken)
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

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	newPair, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), newPair.AccessTokenExpiresAt, time.Minute,
		"rotated access token must use the issuer's AccessTTL, not the provider-supplied expiry")
}

func TestRotate_ConcurrentSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	const n = 16
	var success int32
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if _, err := svc.Rotate(ctx, "", pair.RefreshToken); err == nil {
				atomic.AddInt32(&success, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&success), "exactly one concurrent rotation of the same token may succeed")
}

// TestRotate_ClaimsProviderReceivesRotationContext is the regression test for TASK-068:
// during refresh rotation the ClaimsProvider received only (userID, tenantID) and had no
// way to identify the refresh family/session being rotated. Without that context a provider
// cannot preserve per-session AMR (the documented "re-evaluated, not frozen" semantics are
// impossible to implement correctly): it can neither know which family it is rotating nor
// what assurance that family originally proved. The issuer must surface the rotation context
// (at minimum the family ID and the family's preserved AuthTime) to the provider.
func TestRotate_ClaimsProviderReceivesRotationContext(t *testing.T) {
	ctx := context.Background()

	authTime := time.Now().Add(-2 * time.Hour).UTC()

	var gotRC tokens.RotationContext
	var gotOK bool
	provider := tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		gotRC, gotOK = tokens.RotationContextFromContext(ctx)
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
	})
	svc, store := newRotatingService(t, provider, 24*time.Hour)

	userID := uuid.Must(uuid.NewV7())
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID, AuthTime: authTime})
	require.NoError(t, err)

	// Recover the family ID the issuer recorded for this initial pair so we can assert the
	// provider was told which family it is rotating.
	rt, err := store.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.NoError(t, err)

	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	require.True(t, gotOK, "ClaimsForUser must receive a rotation context identifying the family/session being rotated")
	assert.Equal(t, rt.FamilyID, gotRC.FamilyID, "rotation context must carry the refresh family ID being rotated")
	assert.WithinDuration(t, authTime, gotRC.AuthTime, time.Second, "rotation context must carry the family's preserved auth_time")
}
