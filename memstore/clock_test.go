package memstore_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/limiter"
)

func TestNewWithClockFillsEveryFieldWithEphemeralStores(t *testing.T) {
	s := memstore.NewWithClock(testKEK(t), egauthtest.NewClock(time.Time{}).Library())
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		require.False(t, v.Field(i).IsNil(), "Storage.%s is nil", name)
		require.Equal(t, store.Ephemeral, v.Field(i).Interface().(store.Base).Durability(), "Storage.%s", name)
	}
}

func TestNewWithClockStoresFollowTheTestClock(t *testing.T) {
	ctx := context.Background()
	clk := egauthtest.NewClock(time.Time{})
	s := memstore.NewWithClock(testKEK(t), clk.Library())
	key := limiter.Key{Class: limiter.SelfTest, Value: "probe"}
	budget := limiter.SelfTest.Budget()
	for range budget.Burst {
		d, err := s.Limiter.Allow(ctx, key)
		require.NoError(t, err)
		require.True(t, d.Allowed)
	}
	d, err := s.Limiter.Allow(ctx, key)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	clk.Advance(budget.Refill)
	d, err = s.Limiter.Allow(ctx, key)
	require.NoError(t, err)
	require.True(t, d.Allowed, "the limiter must refill when the test clock advances")
}
