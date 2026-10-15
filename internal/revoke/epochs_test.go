package revoke_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	idmemory "github.com/JLugagne/egauth/store/identity/memory"
)

type flakyEpochs struct {
	identity.Store
	failFeed atomic.Bool
	failRead atomic.Bool
	reads    atomic.Int64
}

func (f *flakyEpochs) CurrentEpoch(ctx context.Context, s principal.Subject) (uint64, error) {
	f.reads.Add(1)
	if f.failRead.Load() {
		return 0, errDown
	}
	return f.Store.CurrentEpoch(ctx, s)
}

func (f *flakyEpochs) EpochsChangedSince(ctx context.Context, c store.Cursor) ([]identity.EpochChange, store.Cursor, error) {
	if f.failFeed.Load() {
		return nil, c, errDown
	}
	return f.Store.EpochsChangedSince(ctx, c)
}

type epochEnv struct {
	clk    *clock.Test
	store  *idmemory.Store
	src    *flakyEpochs
	cache  *revoke.Epochs
	events *recorder
}

func newEpochEnv(t *testing.T) *epochEnv {
	t.Helper()
	clk := clock.NewTest(start)
	st := idmemory.NewWithClock(clk.Clock())
	src := &flakyEpochs{Store: st}
	rec := &recorder{}
	cache, err := revoke.NewEpochs(src, revoke.Config{Clock: clk.Clock(), Events: rec})
	require.NoError(t, err)
	t.Cleanup(cache.Stop)
	return &epochEnv{clk: clk, store: st, src: src, cache: cache, events: rec}
}

func (e *epochEnv) user(t *testing.T, email string) (principal.Subject, uint64) {
	t.Helper()
	id, err := identity.NewIdentifier(identity.IdentifierEmail, email)
	require.NoError(t, err)
	a, err := e.store.Apply(context.Background(), identity.CreateVerified{Tenant: tenant(t, "acme"), Email: id})
	require.NoError(t, err)
	return a.Subject, a.NewEpoch
}

func (e *epochEnv) disable(t *testing.T, s principal.Subject) uint64 {
	t.Helper()
	a, err := e.store.Apply(context.Background(), identity.SetDisabledState{Subject: s, Disable: true})
	require.NoError(t, err)
	return a.NewEpoch
}

func TestEpochsFollowTheFeed(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, epoch := e.user(t, "alice@example.com")
	require.NoError(t, e.cache.Poll(ctx))

	require.NoError(t, e.cache.Check(ctx, s, epoch))
	reads := e.src.reads.Load()
	require.NoError(t, e.cache.Check(ctx, s, epoch))
	require.Equal(t, reads, e.src.reads.Load(), "a fresh cached epoch is served without a store read")

	bumped := e.disable(t, s)
	require.Greater(t, bumped, epoch)
	require.NoError(t, e.cache.Poll(ctx))
	require.ErrorIs(t, e.cache.Check(ctx, s, epoch), revoke.ErrStaleEpoch)
	require.NoError(t, e.cache.Check(ctx, s, bumped))
	got, err := e.cache.Current(ctx, s)
	require.NoError(t, err)
	require.Equal(t, bumped, got)
}

func TestEpochsUnknownSubjectIsStale(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	require.NoError(t, e.cache.Poll(ctx))
	s := principal.Subject{Tenant: tenant(t, "acme"), User: uuid.New()}
	require.ErrorIs(t, e.cache.Check(ctx, s, 0), revoke.ErrStaleEpoch)
	_, err := e.cache.Current(ctx, s)
	require.ErrorIs(t, err, store.ErrNotFound)
	require.Zero(t, e.events.count(event.RevocationUnavailable))
}

func TestEpochsNeverStartedPollerRejectsStaleEpoch(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, epoch := e.user(t, "alice@example.com")
	require.NoError(t, e.cache.Check(ctx, s, epoch))
	e.disable(t, s)
	require.ErrorIs(t, e.cache.Check(ctx, s, epoch), revoke.ErrStaleEpoch)
}

func TestEpochsDeadPollerRejectsStaleEpoch(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, epoch := e.user(t, "alice@example.com")
	e.cache.Start()
	require.Eventually(t, func() bool { return e.cache.Ready() == nil }, 5*time.Second, time.Millisecond)
	require.NoError(t, e.cache.Check(ctx, s, epoch))
	e.cache.Stop()
	e.cache.Stop()

	e.disable(t, s)
	e.clk.Advance(revoke.PollBound)
	require.ErrorIs(t, e.cache.Check(ctx, s, epoch), revoke.ErrStaleEpoch)
}

func TestEpochsFailingPollSourceFailsClosedThenRecovers(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, epoch := e.user(t, "alice@example.com")
	require.NoError(t, e.cache.Poll(ctx))
	require.NoError(t, e.cache.Check(ctx, s, epoch))

	e.src.failFeed.Store(true)
	require.Error(t, e.cache.Poll(ctx))
	bumped := e.disable(t, s)
	e.clk.Advance(revoke.PollBound)
	require.ErrorIs(t, e.cache.Check(ctx, s, epoch), revoke.ErrStaleEpoch)

	e.src.failRead.Store(true)
	require.ErrorIs(t, e.cache.Check(ctx, s, bumped), revoke.ErrUnavailable)
	require.Equal(t, 1, e.events.count(event.RevocationUnavailable))

	e.src.failFeed.Store(false)
	e.src.failRead.Store(false)
	require.NoError(t, e.cache.Poll(ctx))
	require.NoError(t, e.cache.Check(ctx, s, bumped))
}

func TestEpochsHaveNoTimeCutoff(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, _ := e.user(t, "alice@example.com")
	bumped := e.disable(t, s)
	require.NoError(t, e.cache.Poll(ctx))
	require.NoError(t, e.cache.Check(ctx, s, bumped), "a session sealed with the current epoch right after a bump is accepted (T-04)")
	e.clk.Advance(time.Hour)
	require.NoError(t, e.cache.Poll(ctx))
	require.NoError(t, e.cache.Check(ctx, s, bumped))
}

func TestEpochsAcceptASealedEpochNewerThanTheCacheBeforeThePoll(t *testing.T) {
	ctx := context.Background()
	e := newEpochEnv(t)
	s, epoch := e.user(t, "carol@example.com")
	require.NoError(t, e.cache.Poll(ctx))
	require.NoError(t, e.cache.Check(ctx, s, epoch))

	bumped := e.disable(t, s)
	require.Greater(t, bumped, epoch)

	require.NoError(t, e.cache.Check(ctx, s, bumped), "an epoch minted by a write the cache has not polled yet is current")
	require.ErrorIs(t, e.cache.Check(ctx, s, epoch), revoke.ErrStaleEpoch)
	require.ErrorIs(t, e.cache.Check(ctx, s, bumped+1), revoke.ErrStaleEpoch, "an epoch above the store's is never accepted")
}
