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
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/sessions/memory"
	"github.com/JLugagne/egauth/store/sessions/storetest"
)

var clocks sync.Map

func travel(t *testing.T, s sessions.Store, d time.Duration) {
	t.Helper()
	tc, ok := clocks.Load(s)
	require.True(t, ok, "store was not built by this test")
	tc.(*clock.Test).Advance(d)
}

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{Restore: sessions.Restore, Travel: travel})
	storetest.Run(t, func(t *testing.T) sessions.Store {
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
	r, err := sessions.NewRecord(sessions.Spec{
		ID:                uuid.New(),
		TokenHash:         make([]byte, sessions.HashLen),
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
