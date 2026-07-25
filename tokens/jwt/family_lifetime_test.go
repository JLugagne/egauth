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

// familyCapBase is a frozen instant far from wall time so the injected clock is provably the
// only time source used by the family-lifetime cap.
var familyCapBase = time.Date(2035, 6, 1, 12, 0, 0, 0, time.UTC)

// newCappedService builds a rotating issuer whose clock is the returned pointer, so a test can
// advance time by writing through it.
func newCappedService(t *testing.T, mutate func(*jwt.Config[struct{}])) (*jwt.Service[struct{}], *memory.Store[struct{}], *time.Time) {
	t.Helper()
	now := familyCapBase
	store := memory.NewStore[struct{}]()
	cfg := jwt.Config[struct{}]{
		Store:          store,
		SecretKey:      "family-cap-secret-aaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     time.Hour,
		ClaimsProvider: okProvider(t),
		Clock:          func() time.Time { return now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return jwt.New[struct{}](cfg), store, &now
}

// TestRotate_FamilyAbsoluteLifetimeCap proves a refresh-token FAMILY dies at its absolute
// deadline (anchored on the family's creation) no matter how often it is rotated: every
// rotation is CLAMPED to the deadline instead of resetting the full RefreshTTL, so a family
// kept warm by a stolen token cannot live forever.
func TestRotate_FamilyAbsoluteLifetimeCap(t *testing.T) {
	ctx := context.Background()
	svc, _, now := newCappedService(t, func(cfg *jwt.Config[struct{}]) {
		cfg.MaxRefreshFamilyLifetime = 3 * time.Hour
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	deadline := familyCapBase.Add(3 * time.Hour)
	current := pair
	for i := 1; i <= 5; i++ {
		*now = familyCapBase.Add(time.Duration(i) * 30 * time.Minute)
		next, rerr := svc.Rotate(ctx, "", current.RefreshToken)
		require.NoError(t, rerr, "rotation %d is inside the family lifetime and must succeed", i)
		assert.False(t, next.RefreshTokenExpiresAt.After(deadline),
			"rotation %d must be clamped to the family deadline, never pushed past it", i)
		current = next
	}
	assert.Equal(t, deadline, current.RefreshTokenExpiresAt,
		"the last rotation inside the window must expire exactly at the family deadline")

	*now = deadline.Add(time.Second)
	_, err = svc.Rotate(ctx, "", current.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrTokenExpired,
		"past the absolute family deadline the family must be dead despite continuous rotation")
}

// TestRotate_FamilyCapIsOnByDefault proves the cap is NOT opt-in: an issuer configured without
// any family-lifetime setting still stops a continuously rotated family at the default deadline.
func TestRotate_FamilyCapIsOnByDefault(t *testing.T) {
	ctx := context.Background()
	svc, _, now := newCappedService(t, func(cfg *jwt.Config[struct{}]) {
		cfg.RefreshTTL = 15 * 24 * time.Hour
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	assert.Equal(t, familyCapBase.Add(15*24*time.Hour), pair.RefreshTokenExpiresAt,
		"the default cap must never shorten the configured RefreshTTL of a fresh family")

	deadline := familyCapBase.Add(jwt.DefaultMaxRefreshFamilyLifetime)
	current := pair
	for _, d := range []time.Duration{10 * 24 * time.Hour, 20 * 24 * time.Hour, 29 * 24 * time.Hour} {
		*now = familyCapBase.Add(d)
		current, err = svc.Rotate(ctx, "", current.RefreshToken)
		require.NoError(t, err)
		assert.False(t, current.RefreshTokenExpiresAt.After(deadline),
			"a rotation at +%s must be clamped to the default family deadline", d)
	}

	*now = deadline.Add(time.Second)
	_, err = svc.Rotate(ctx, "", current.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrTokenExpired, "the default cap must expire the family")
}

// TestRotate_FamilyCapNegativeValueDoesNotDisable pins the fail-safe normalisation: a negative
// MaxRefreshFamilyLifetime is a misconfiguration and must fall back to the secure default, never
// silently disable the cap.
func TestRotate_FamilyCapNegativeValueDoesNotDisable(t *testing.T) {
	ctx := context.Background()
	svc, _, now := newCappedService(t, func(cfg *jwt.Config[struct{}]) {
		cfg.RefreshTTL = 15 * 24 * time.Hour
		cfg.MaxRefreshFamilyLifetime = -time.Hour
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	*now = familyCapBase.Add(10 * 24 * time.Hour)
	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	*now = familyCapBase.Add(jwt.DefaultMaxRefreshFamilyLifetime + time.Second)
	_, err = svc.Rotate(ctx, "", rotated.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrTokenExpired, "a negative cap must not disable the default cap")
}

// TestRotate_FamilyCapContradictionFailsSecure pins that combining an explicit cap with the
// explicit disable flag keeps the CAP (fail secure); Validate reports the contradiction.
func TestRotate_FamilyCapContradictionFailsSecure(t *testing.T) {
	ctx := context.Background()
	svc, _, now := newCappedService(t, func(cfg *jwt.Config[struct{}]) {
		cfg.MaxRefreshFamilyLifetime = 2 * time.Hour
		cfg.DisableMaxRefreshFamilyLifetime = true
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	*now = familyCapBase.Add(2*time.Hour + time.Second)
	_, err = svc.Rotate(ctx, "", pair.RefreshToken)
	assert.ErrorIs(t, err, tokens.ErrTokenExpired, "an explicit cap must win over the disable flag")
}

// TestRotate_FamilyCapCanBeDisabledExplicitly proves the escape hatch works on its own: with
// DisableMaxRefreshFamilyLifetime and no cap value, a family rotates past the default deadline.
func TestRotate_FamilyCapCanBeDisabledExplicitly(t *testing.T) {
	ctx := context.Background()
	svc, _, now := newCappedService(t, func(cfg *jwt.Config[struct{}]) {
		cfg.RefreshTTL = 15 * 24 * time.Hour
		cfg.DisableMaxRefreshFamilyLifetime = true
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	current := pair
	for _, d := range []time.Duration{10 * 24 * time.Hour, 20 * 24 * time.Hour, 30 * 24 * time.Hour, 40 * 24 * time.Hour} {
		*now = familyCapBase.Add(d)
		current, err = svc.Rotate(ctx, "", current.RefreshToken)
		require.NoError(t, err, "with the cap disabled the family must keep rotating at +%s", d)
		assert.Equal(t, now.Add(15*24*time.Hour), current.RefreshTokenExpiresAt,
			"with no cap each rotation gets the full RefreshTTL")
	}
}

// TestValidate_FamilyLifetimeMisconfiguration pins that Config.Validate surfaces both a negative
// cap and the cap/disable contradiction at startup instead of leaving them to be normalised silently.
func TestValidate_FamilyLifetimeMisconfiguration(t *testing.T) {
	base := jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		ClaimsProvider: okProvider(t),
		SecretKey:      "family-cap-secret-aaaaaaaaaaaaaaa!",
		Issuer:         "egauth-test",
		AccessTTL:      time.Minute,
		RefreshTTL:     time.Hour,
	}

	ok := base
	require.NoError(t, ok.Validate())

	negative := base
	negative.MaxRefreshFamilyLifetime = -time.Second
	assert.ErrorContains(t, negative.Validate(), "MaxRefreshFamilyLifetime")

	contradiction := base
	contradiction.MaxRefreshFamilyLifetime = time.Hour
	contradiction.DisableMaxRefreshFamilyLifetime = true
	assert.ErrorContains(t, contradiction.Validate(), "DisableMaxRefreshFamilyLifetime")
}
