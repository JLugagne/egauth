package revoke_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
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
	"github.com/JLugagne/egauth/store/tokens"
	"github.com/JLugagne/egauth/store/tokens/memory"
)

var start = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

var digests atomic.Uint64

func digest() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], digests.Add(1))
	sum := sha256.Sum256(append([]byte("revoke-test"), b[:]...))
	return sum[:]
}

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	require.NoError(t, err)
	return id
}

func subject(t *testing.T) principal.Subject {
	return principal.Subject{Tenant: tenant(t, "acme"), User: uuid.New()}
}

type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) EmitEvent(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) count(t event.Type) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Type == t {
			n++
		}
	}
	return n
}

type flaky struct {
	tokens.Store
	failFeed  atomic.Bool
	failState atomic.Bool
	states    atomic.Int64
}

var errDown = errors.New("store down")

func (f *flaky) FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (tokens.FamilyState, error) {
	f.states.Add(1)
	if f.failState.Load() {
		return tokens.FamilyState{}, errDown
	}
	return f.Store.FamilyState(ctx, t, family)
}

func (f *flaky) RevocationsSince(ctx context.Context, c store.Cursor) ([]tokens.Revocation, store.Cursor, error) {
	if f.failFeed.Load() {
		return nil, c, errDown
	}
	return f.Store.RevocationsSince(ctx, c)
}

type familyEnv struct {
	clk    *clock.Test
	store  *memory.Store
	src    *flaky
	cache  *revoke.Families
	events *recorder
}

func newFamilyEnv(t *testing.T) *familyEnv {
	t.Helper()
	clk := clock.NewTest(start)
	st := memory.NewWithClock(clk.Clock())
	src := &flaky{Store: st}
	rec := &recorder{}
	cache, err := revoke.NewFamilies(src, revoke.Config{Clock: clk.Clock(), Events: rec})
	require.NoError(t, err)
	t.Cleanup(cache.Stop)
	return &familyEnv{clk: clk, store: st, src: src, cache: cache, events: rec}
}

func (e *familyEnv) family(t *testing.T, s principal.Subject) revoke.Family {
	t.Helper()
	now := e.clk.Now()
	r, err := tokens.RestoreRefreshRecord(tokens.RefreshRow{
		TokenHash:       digest(),
		Family:          uuid.New(),
		Subject:         s,
		Lineage:         uuid.New(),
		Sealed:          principal.SealedFromBytes([]byte("sealed-attrs")),
		IdleExpiresAt:   now.Add(time.Hour),
		FamilyExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:       now,
	})
	require.NoError(t, err)
	require.NoError(t, e.store.Create(context.Background(), r))
	return revoke.Family{ID: r.Family(), Lineage: r.Lineage()}
}

func (e *familyEnv) poll(t *testing.T) {
	t.Helper()
	require.NoError(t, e.cache.Poll(context.Background()))
}

func TestFamiliesLiveAndRevokedThroughPoll(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)

	require.NoError(t, e.cache.Live(ctx, s, f))
	reads := e.src.states.Load()
	require.NoError(t, e.cache.Live(ctx, s, f))
	require.Equal(t, reads, e.src.states.Load(), "a fresh cached entry is served without a store read")

	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	e.poll(t)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive)
}

func TestFamiliesRefuseMismatchedOrUnknownFamily(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)

	require.ErrorIs(t, e.cache.Live(ctx, subject(t), f), revoke.ErrNotLive, "another subject")
	other := principal.Subject{Tenant: tenant(t, "other"), User: s.User}
	require.ErrorIs(t, e.cache.Live(ctx, other, f), revoke.ErrNotLive, "another tenant")
	require.ErrorIs(t, e.cache.Live(ctx, s, revoke.Family{ID: f.ID, Lineage: uuid.New()}), revoke.ErrNotLive, "another lineage")
	require.ErrorIs(t, e.cache.Live(ctx, s, revoke.Family{ID: uuid.New(), Lineage: f.Lineage}), revoke.ErrNotLive, "unknown family")
	require.Zero(t, e.events.count(event.RevocationUnavailable), "a definitive answer is not an outage")
}

func TestFamiliesUnknownIsNeverCached(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	e.poll(t)
	id := uuid.New()
	lineage := uuid.New()
	require.ErrorIs(t, e.cache.Live(ctx, s, revoke.Family{ID: id, Lineage: lineage}), revoke.ErrNotLive)

	now := e.clk.Now()
	r, err := tokens.RestoreRefreshRecord(tokens.RefreshRow{
		TokenHash: digest(), Family: id, Subject: s, Lineage: lineage,
		Sealed:        principal.SealedFromBytes([]byte("sealed-attrs")),
		IdleExpiresAt: now.Add(time.Hour), FamilyExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	require.NoError(t, err)
	require.NoError(t, e.store.Create(ctx, r))
	require.NoError(t, e.cache.Live(ctx, s, revoke.Family{ID: id, Lineage: lineage}), "creation is not in the feed, so a miss is never cached")
}

func TestFamiliesExpiryIsCheckedAtUse(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, f))
	e.clk.Advance(25 * time.Hour)
	e.poll(t)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive)
}

func TestFamiliesNeverStartedPollerRejectsRevokedSid(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	require.NoError(t, e.cache.Live(ctx, s, f))
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive, "with no poll at all every check reads the store")
	require.ErrorIs(t, e.cache.Ready(), revoke.ErrStale)
}

func TestFamiliesDeadPollerRejectsRevokedSid(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.cache.Start()
	require.Eventually(t, func() bool { return e.cache.Ready() == nil }, 5*time.Second, time.Millisecond, "Start polls at once")
	require.NoError(t, e.cache.Live(ctx, s, f))
	e.cache.Stop()

	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	e.clk.Advance(revoke.PollBound)
	require.ErrorIs(t, e.cache.Ready(), revoke.ErrStale)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive, "an entry is trusted only while the last poll is younger than PollBound")
}

func TestFamiliesEntryTrustedOnlyWithinPollBound(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, f))
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	e.clk.Advance(revoke.PollBound - time.Nanosecond)
	require.NoError(t, e.cache.Live(ctx, s, f), "within PollBound the cache may lag")
	e.clk.Advance(time.Nanosecond)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive, "at PollBound the store decides")
}

func TestFamiliesFailingPollSourceFailsClosedThenRecovers(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, f))

	e.src.failFeed.Store(true)
	require.Error(t, e.cache.Poll(ctx))
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	e.clk.Advance(revoke.PollBound)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive, "a failing feed never keeps a stale entry trusted")

	g := e.family(t, s)
	e.src.failState.Store(true)
	err := e.cache.Live(ctx, s, g)
	require.ErrorIs(t, err, revoke.ErrUnavailable, "store unreachable: 503 auth_unavailable")
	require.NotErrorIs(t, err, revoke.ErrNotLive)
	require.Equal(t, 1, e.events.count(event.RevocationUnavailable))

	e.src.failFeed.Store(false)
	e.src.failState.Store(false)
	e.poll(t)
	require.NoError(t, e.cache.Ready())
	require.NoError(t, e.cache.Live(ctx, s, g), "the next check after recovery succeeds")
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive)
}

func TestFamiliesMissFailureIsUnavailable(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)
	e.src.failState.Store(true)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrUnavailable)
	require.Equal(t, 1, e.events.count(event.RevocationUnavailable))
}

func TestFamiliesBackdatedRevocationIsSeen(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, f))

	e.clk.Advance(-time.Hour)
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	e.clk.Advance(time.Hour)
	e.poll(t)
	require.ErrorIs(t, e.cache.Live(ctx, s, f), revoke.ErrNotLive, "positions are store-issued, so a back-dated revocation still reaches the cache (C-18)")
}

func TestFamiliesHaveNoTimeCutoff(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	old := e.family(t, s)
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, old.ID))

	fresh := e.family(t, s)
	e.poll(t)
	require.ErrorIs(t, e.cache.Live(ctx, s, old), revoke.ErrNotLive, "a revocation older than the cache is found by lookup, with no backfill")
	require.NoError(t, e.cache.Live(ctx, s, fresh), "a family created in the same instant as a revocation of the subject stays live (T-04)")

	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, old.ID))
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, fresh), "revoking one family never cuts off the subject's other families")
	e.clk.Advance(12 * time.Hour)
	e.poll(t)
	require.NoError(t, e.cache.Live(ctx, s, fresh), "a revoked user is not locked out of later sessions")
}

func TestFamiliesLookupRacingAPollIsNotCached(t *testing.T) {
	ctx := context.Background()
	e := newFamilyEnv(t)
	s := subject(t)
	f := e.family(t, s)
	e.poll(t)

	gate := make(chan struct{})
	released := make(chan struct{})
	blocking := &blockingSource{flaky: e.src, gate: gate, entered: released}
	cache, err := revoke.NewFamilies(blocking, revoke.Config{Clock: e.clk.Clock()})
	require.NoError(t, err)
	require.NoError(t, cache.Poll(ctx))

	blocking.block.Store(true)
	done := make(chan error, 1)
	go func() { done <- cache.Live(ctx, s, f) }()
	<-released
	blocking.block.Store(false)
	require.NoError(t, e.store.RevokeFamily(ctx, s.Tenant, f.ID))
	require.NoError(t, cache.Poll(ctx))
	close(gate)
	require.NoError(t, <-done, "the lookup read the store before the revocation")

	require.ErrorIs(t, cache.Live(ctx, s, f), revoke.ErrNotLive, "a lookup that raced a poll is not cached, so the revocation is not lost")
}

type blockingSource struct {
	*flaky
	block   atomic.Bool
	gate    chan struct{}
	entered chan struct{}
}

func (b *blockingSource) FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (tokens.FamilyState, error) {
	if !b.block.Load() {
		return b.flaky.FamilyState(ctx, t, family)
	}
	st, err := b.flaky.FamilyState(ctx, t, family)
	close(b.entered)
	<-b.gate
	return st, err
}

func TestFamiliesConfigValidation(t *testing.T) {
	_, err := revoke.NewFamilies(nil, revoke.Config{})
	require.ErrorIs(t, err, revoke.ErrInvalidConfig)
	_, err = revoke.NewFamilies(memory.New(), revoke.Config{Capacity: -1})
	require.ErrorIs(t, err, revoke.ErrInvalidConfig)
}
