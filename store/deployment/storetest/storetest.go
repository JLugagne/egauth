// Package storetest holds the conformance suite of deployment.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/deployment"
)

const goroutines = 32

// Run exercises the deployment.Store contract against stores returned by newStore. Each subtest gets
// a fresh store, so subtests never share keys or instances.
func Run(t *testing.T, newStore func(*testing.T) deployment.Store) {
	t.Helper()
	suites := map[string]func(*testing.T, deployment.Store){
		"Base":                baseSuite,
		"SealedValues":        sealedValues,
		"PutIfAbsentRace":     putIfAbsentRace,
		"ReplaceSealed":       replaceSealed,
		"ReplaceSealedRace":   replaceSealedRace,
		"HeartbeatLiveness":   heartbeatLiveness,
		"ReapKeepsLiveValues": reapKeepsLiveValues,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

func baseSuite(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	require.NoError(t, s.Ping(ctx))
	require.True(t, s.Durability().Valid())

	stored, err := s.PutSealedIfAbsent(ctx, "canary", []byte("sealed"))
	require.NoError(t, err)
	require.True(t, stored)
	tenant, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	require.NoError(t, s.EraseTenant(ctx, tenant))
	require.NoError(t, s.EraseTenant(ctx, principal.TenantID{}))
	got, err := s.GetSealed(ctx, "canary")
	require.NoError(t, err)
	require.Equal(t, []byte("sealed"), got, "deployment values belong to no tenant")
}

func sealedValues(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	_, err := s.GetSealed(ctx, "missing")
	require.ErrorIs(t, err, store.ErrNotFound)

	in := []byte("sealed-bytes")
	stored, err := s.PutSealedIfAbsent(ctx, "k", in)
	require.NoError(t, err)
	require.True(t, stored)
	in[0] = 'X'

	got, err := s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("sealed-bytes"), got, "the store keeps its own copy")
	got[0] = 'Y'
	again, err := s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("sealed-bytes"), again, "a returned slice never aliases the store")

	stored, err = s.PutSealedIfAbsent(ctx, "k", []byte("other"))
	require.NoError(t, err)
	require.False(t, stored)
	again, err = s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("sealed-bytes"), again)

	_, err = s.PutSealedIfAbsent(ctx, "", []byte("x"))
	require.Error(t, err)
	_, err = s.PutSealedIfAbsent(ctx, "empty", nil)
	require.Error(t, err)
}

func putIfAbsentRace(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := s.PutSealedIfAbsent(ctx, "race", []byte{byte(i + 1)})
			if err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
}

func replaceSealed(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	_, err := s.ReplaceSealed(ctx, "absent", deployment.Replacement{Old: []byte("a"), New: []byte("b")})
	require.ErrorIs(t, err, store.ErrNotFound)

	_, err = s.PutSealedIfAbsent(ctx, "k", []byte("one"))
	require.NoError(t, err)

	swapped, err := s.ReplaceSealed(ctx, "k", deployment.Replacement{Old: []byte("wrong"), New: []byte("two")})
	require.NoError(t, err)
	require.False(t, swapped)
	got, err := s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("one"), got)

	swapped, err = s.ReplaceSealed(ctx, "k", deployment.Replacement{Old: []byte("one"), New: []byte("two")})
	require.NoError(t, err)
	require.True(t, swapped)
	got, err = s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("two"), got)

	swapped, err = s.ReplaceSealed(ctx, "k", deployment.Replacement{Old: []byte("one"), New: []byte("three")})
	require.NoError(t, err)
	require.False(t, swapped, "the old value no longer matches")

	_, err = s.ReplaceSealed(ctx, "k", deployment.Replacement{Old: []byte("two"), New: nil})
	require.Error(t, err)
}

func replaceSealedRace(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	_, err := s.PutSealedIfAbsent(ctx, "k", []byte("old"))
	require.NoError(t, err)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := s.ReplaceSealed(ctx, "k", deployment.Replacement{Old: []byte("old"), New: []byte{byte(i + 1)}})
			if err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "a compare-and-swap succeeds for exactly one caller")
	got, err := s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.False(t, bytes.Equal(got, []byte("old")))
}

func heartbeatLiveness(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	_, err := s.Heartbeat(ctx, uuid.Nil)
	require.Error(t, err)

	first, second := uuid.New(), uuid.New()
	before := clock.Clock{}.Now().Add(-time.Second)
	live, err := s.Heartbeat(ctx, first)
	require.NoError(t, err)
	require.Len(t, live, 1)
	require.Equal(t, first, live[0].ID)
	require.True(t, live[0].StartedAt.After(before))
	require.False(t, live[0].LastSeenAt.Before(live[0].StartedAt))
	startedAt := live[0].StartedAt

	live, err = s.Heartbeat(ctx, second)
	require.NoError(t, err)
	require.Len(t, live, 2)

	live, err = s.Heartbeat(ctx, first)
	require.NoError(t, err)
	require.Len(t, live, 2, "a repeated heartbeat never counts an instance twice")
	for _, in := range live {
		if in.ID == first {
			require.True(t, in.StartedAt.Equal(startedAt), "StartedAt is the first heartbeat")
			require.False(t, in.LastSeenAt.Before(startedAt))
		}
	}

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Heartbeat(ctx, uuid.New())
		}()
	}
	wg.Wait()
	live, err = s.Heartbeat(ctx, first)
	require.NoError(t, err)
	require.Len(t, live, 2+goroutines)
}

func reapKeepsLiveValues(t *testing.T, s deployment.Store) {
	ctx := context.Background()
	_, err := s.PutSealedIfAbsent(ctx, "k", []byte("v"))
	require.NoError(t, err)
	id := uuid.New()
	_, err = s.Heartbeat(ctx, id)
	require.NoError(t, err)

	n, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	got, err := s.GetSealed(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
	live, err := s.Heartbeat(ctx, id)
	require.NoError(t, err)
	require.Len(t, live, 1)
}
