package memory_test

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
	"github.com/JLugagne/egauth/store/tokens/memory"
	"github.com/JLugagne/egauth/store/tokens/storetest"
)

var clocks sync.Map

func travel(t *testing.T, s tokens.Store, d time.Duration) {
	t.Helper()
	tc, ok := clocks.Load(s)
	require.True(t, ok, "store was not built by this test")
	tc.(*clock.Test).Advance(d)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{Restore: tokens.RestoreRefreshRecord, Travel: travel})
	storetest.Run(t, func(t *testing.T) tokens.Store {
		tc := clock.NewTest(clock.Clock{}.Now())
		s := memory.NewWithClock(tc.Clock())
		clocks.Store(s, tc)
		t.Cleanup(func() { clocks.Delete(s) })
		return s
	})
}

func TestStoreIsEphemeral(t *testing.T) {
	require.Equal(t, store.Ephemeral, memory.New().Durability())
}

func TestFullAttrsUnsealAfterTheStoreRoundTrip(t *testing.T) {
	full := principaltest.Full()
	now := clock.Clock{}.Now()
	r, err := tokens.NewRefreshRecord(tokens.RefreshSpec{
		TokenHash:         make([]byte, tokens.HashLen),
		Family:            uuid.New(),
		Attrs:             full,
		AppClaims:         []byte(`{"a":1}`),
		ClientFingerprint: []byte("fp"),
		IdleTTL:           time.Hour,
		MaxLifetime:       now.Sub(full.CreatedAt()) + 24*time.Hour,
		Now:               now,
	}, core.Seal)
	require.NoError(t, err)
	s := memory.New()
	require.NoError(t, s.Create(context.Background(), r))
	got, err := s.Get(context.Background(), r.Tenant(), r.TokenHash())
	require.NoError(t, err)
	back, err := core.Unseal(got.Sealed())
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(full, back), "round trip differs:\n%#v\n%#v", full, back)
}

func TestGraceIsDecidedByTheStoreClockNotTheWallClock(t *testing.T) {
	tc := clock.NewTest(clock.Clock{}.Now().Add(-time.Hour))
	s := memory.NewWithClock(tc.Clock())
	full := principaltest.Full()
	life := clock.Clock{}.Now().Sub(full.CreatedAt()) + 24*time.Hour
	spec := func(hash byte, fp string) tokens.RefreshRecord {
		r, err := tokens.NewRefreshRecord(tokens.RefreshSpec{
			TokenHash:         append(make([]byte, tokens.HashLen-1), hash),
			Family:            uuid.MustParse("7f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"),
			Attrs:             full,
			ClientFingerprint: []byte(fp),
			IdleTTL:           3 * time.Hour,
			MaxLifetime:       life,
			Now:               clock.Clock{}.Now(),
		}, core.Seal)
		require.NoError(t, err)
		return r
	}
	ctx := context.Background()
	a := spec(1, "fp")
	require.NoError(t, s.Create(ctx, a))
	_, err := s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: spec(2, "fp")})
	require.NoError(t, err)
	_, err = s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash(), Next: spec(3, "fp")})
	require.ErrorIs(t, err, tokens.ErrConcurrent, "an hour between the store clock and the wall clock is irrelevant")
}
