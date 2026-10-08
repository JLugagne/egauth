package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/keys/memory"
	"github.com/JLugagne/egauth/store/keys/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{
		SeedV016: func(t *testing.T, s keys.Store, k keys.Key) {
			t.Helper()
			s.(*memory.Store).AddV016(k)
		},
		AgeFeed: func(t *testing.T, s keys.Store, d time.Duration) {
			t.Helper()
			s.(*memory.Store).BackdateFeed(d)
		},
	})
	storetest.Run(t, func(*testing.T) keys.Store { return memory.New() })
}

func TestStoreIsEphemeral(t *testing.T) {
	require.Equal(t, store.Ephemeral, memory.New().Durability())
}

func TestReapPrunesOldFeedEntries(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	require.NoError(t, s.CreateTenant(ctx, keys.Key{
		Tenant: tn, KeyID: "k1", Alg: "EdDSA", Sealed: []byte("x"), AADVersion: keys.AADVersionCurrent,
	}))
	require.Equal(t, 1, s.FeedLen())
	s.BackdateFeed(48 * time.Hour)
	_, err = s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, s.FeedLen())
}
