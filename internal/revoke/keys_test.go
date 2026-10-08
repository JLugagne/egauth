package revoke_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

type keyFeed struct {
	mu      sync.Mutex
	changes []principal.TenantID
	pruned  int
	page    int
	fail    error
	version map[principal.TenantID]int
	loads   int
}

func newKeyFeed() *keyFeed { return &keyFeed{version: map[principal.TenantID]int{}} }

func (f *keyFeed) change(t principal.TenantID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version[t]++
	f.changes = append(f.changes, t)
}

func (f *keyFeed) ChangesSince(_ context.Context, c store.Cursor) ([]keys.Change, store.Cursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, c, f.fail
	}
	pos := int(c.Position())
	if pos != 0 && pos < f.pruned {
		return nil, c, errors.Join(store.ErrNotFound, errors.New("cursor older than the retained feed"))
	}
	pos = max(pos, f.pruned)
	var out []keys.Change
	for i := pos; i < len(f.changes); i++ {
		if f.page > 0 && len(out) == f.page {
			break
		}
		out = append(out, keys.Change{Tenant: f.changes[i]})
		pos = i + 1
	}
	return out, store.RestoreCursor(uint64(pos)), nil
}

func (f *keyFeed) load(_ context.Context, t principal.TenantID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	return f.version[t], nil
}

func (f *keyFeed) loadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads
}

func newKeys(t *testing.T, f *keyFeed, cfg revoke.Config) *revoke.Keys[int] {
	t.Helper()
	k, err := revoke.NewKeys(f, f.load, cfg)
	require.NoError(t, err)
	t.Cleanup(k.Stop)
	return k
}

func TestKeysFollowTheChangeFeed(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	f := newKeyFeed()
	a, b := tenant(t, "a"), tenant(t, "b")
	f.change(a)
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock()})
	require.NoError(t, k.Poll(ctx))

	v, err := k.Get(ctx, a)
	require.NoError(t, err)
	require.Equal(t, 1, v)
	_, err = k.Get(ctx, b)
	require.NoError(t, err)
	loads := f.loadCount()
	_, _ = k.Get(ctx, a)
	_, _ = k.Get(ctx, b)
	require.Equal(t, loads, f.loadCount(), "both tenants are cached, the empty keyset included")

	f.change(a)
	require.NoError(t, k.Poll(ctx))
	v, err = k.Get(ctx, a)
	require.NoError(t, err)
	require.Equal(t, 2, v, "a keyset change on another instance reaches this cache through ChangesSince (T-15)")
	_, _ = k.Get(ctx, b)
	require.Equal(t, loads+1, f.loadCount(), "only the changed tenant is looked up again")
}

func TestKeysForgetDropsTheEntryAndRacingLookups(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	f := newKeyFeed()
	a := tenant(t, "a")
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock()})
	require.NoError(t, k.Poll(ctx))
	_, err := k.Get(ctx, a)
	require.NoError(t, err)
	f.mu.Lock()
	f.version[a] = 7
	f.mu.Unlock()
	k.Forget(a)
	v, err := k.Get(ctx, a)
	require.NoError(t, err)
	require.Equal(t, 7, v)
}

func TestKeysFeedGapResetsTheCache(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	f := newKeyFeed()
	a := tenant(t, "a")
	f.change(a)
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock()})
	require.NoError(t, k.Poll(ctx))
	_, err := k.Get(ctx, a)
	require.NoError(t, err)

	f.change(a)
	f.change(tenant(t, "b"))
	f.mu.Lock()
	f.pruned = 3
	f.mu.Unlock()
	clk.Advance(revoke.PollInterval)
	require.NoError(t, k.Poll(ctx), "a pruned cursor drops every entry and resumes from the start of the feed")
	v, err := k.Get(ctx, a)
	require.NoError(t, err)
	require.Equal(t, 2, v, "the change hidden by the gap is not lost")
}

func TestKeysPollReadsEveryPage(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	f := newKeyFeed()
	f.page = 1
	a := tenant(t, "a")
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock()})
	require.NoError(t, k.Poll(ctx))
	_, err := k.Get(ctx, a)
	require.NoError(t, err)
	for range 5 {
		f.change(tenant(t, "noise"))
	}
	f.change(a)
	require.NoError(t, k.Poll(ctx))
	v, err := k.Get(ctx, a)
	require.NoError(t, err)
	require.Equal(t, 1, v, "a change behind several pages is applied in the same poll")
}

func TestKeysUnavailable(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	rec := &recorder{}
	f := newKeyFeed()
	failing := func(context.Context, principal.TenantID) (int, error) { return 0, errDown }
	k, err := revoke.NewKeys(f, failing, revoke.Config{Clock: clk.Clock(), Events: rec})
	require.NoError(t, err)
	_, err = k.Get(ctx, tenant(t, "a"))
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	require.ErrorIs(t, err, errDown)
	require.Equal(t, 1, rec.count(event.RevocationUnavailable))

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = k.Get(cancelled, tenant(t, "a"))
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	require.Equal(t, 1, rec.count(event.RevocationUnavailable), "a cancelled request is not an outage")
}

func TestCacheIsABoundedLRU(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	f := newKeyFeed()
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock(), Capacity: 2})
	require.NoError(t, k.Poll(ctx))
	a, b, c := tenant(t, "a"), tenant(t, "b"), tenant(t, "c")
	for _, tn := range []principal.TenantID{a, b, a, c} {
		_, err := k.Get(ctx, tn)
		require.NoError(t, err)
	}
	require.Equal(t, 2, k.Len())
	loads := f.loadCount()
	_, _ = k.Get(ctx, a)
	require.Equal(t, loads, f.loadCount(), "the most recently used entry survives")
	_, _ = k.Get(ctx, b)
	require.Equal(t, loads+1, f.loadCount(), "the least recently used entry was evicted and is looked up again")
	require.Equal(t, 2, k.Len())
}

func TestStartStopAreIdempotentAndRestartable(t *testing.T) {
	clk := clock.NewTest(start)
	f := newKeyFeed()
	k := newKeys(t, f, revoke.Config{Clock: clk.Clock()})
	k.Stop()
	k.Start()
	k.Start()
	require.Eventually(t, func() bool { return k.Ready() == nil }, 5e9, 1e6)
	k.Stop()
	k.Stop()
	clk.Advance(revoke.PollBound)
	require.ErrorIs(t, k.Ready(), revoke.ErrStale)
	k.Start()
	require.Eventually(t, func() bool { return k.Ready() == nil }, 5e9, 1e6)
	k.Stop()
}

func TestPollBoundIsThreePollIntervals(t *testing.T) {
	require.Equal(t, 2e9, float64(revoke.PollInterval))
	require.Equal(t, 3*revoke.PollInterval, revoke.PollBound)
}
