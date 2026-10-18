// Package storetest holds the conformance suite of ceremony.Store implementations.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
)

const (
	goroutines = 32
	subMicro   = 789 * time.Nanosecond
)

// Restorer rebuilds a record from its persisted row. A store implementation's test passes
// ceremony.Restore to Seed.
type Restorer func(ceremony.Row) (ceremony.Record, error)

var restorers sync.Map

// Seed hands Run, for t and its subtests, the constructor it builds historical records with: the
// suite may not call ceremony.Restore itself (G6), so the store implementation's test, which may,
// passes it. Call it before Run on the same t.
func Seed(t *testing.T, restore Restorer) {
	t.Helper()
	restorers.Store(t, restore)
	t.Cleanup(func() { restorers.Delete(t) })
}

// Run exercises the ceremony.Store contract against stores returned by newStore. Each subtest gets
// a fresh store. Time comes from the wall clock, so records are built with historical creation
// instants rather than by advancing a clock. Stores keep instants to the microsecond, truncating
// the rest, and Pending bytes verbatim. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) ceremony.Store) {
	t.Helper()
	v, ok := restorers.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, ceremony.Restore) before Run")
	}
	restore := v.(Restorer)
	suites := map[string]func(*testing.T, ceremony.Store, Restorer){
		"Base":                  baseSuite,
		"PutPeekRoundTrip":      roundTrip,
		"FullPendingRoundTrip":  fullPendingRoundTrip,
		"PutRefusals":           putRefusals,
		"IsolationByTenantKind": isolation,
		"ConsumeSingleUse":      consumeSingleUse,
		"MarkConsumed":          markConsumed,
		"EvictionPerScope":      evictionPerScope,
		"EvictionConcurrent":    evictionConcurrent,
		"IdentifierCeiling":     identifierCeiling,
		"ShortHandles":          shortHandles,
		"Attempts":              attempts,
		"DeleteForScope":        deleteForScope,
		"ReapExpired":           reapExpired,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t), restore) })
	}
}

var counter atomic.Uint64

func now() time.Time { return clock.Clock{}.Now() }

func handle() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter.Add(1))
	sum := sha256.Sum256(b[:])
	return sum[:]
}

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	require.NoError(t, err)
	return id
}

func userScope() []byte {
	u := uuid.New()
	return u[:]
}

func idScope() []byte {
	h := handle()
	return h
}

func scopeFor(k ceremony.Kind) []byte {
	if k.Scope() == ceremony.Subject {
		return userScope()
	}
	return idScope()
}

type spec struct {
	tenant  principal.TenantID
	kind    ceremony.Kind
	handle  []byte
	scope   []byte
	age     time.Duration
	expired bool
	payload []byte
	pending principal.Sealed
}

func build(t *testing.T, restore Restorer, s spec) ceremony.Record {
	t.Helper()
	if s.handle == nil {
		s.handle = handle()
	}
	if s.scope == nil {
		s.scope = scopeFor(s.kind)
	}
	if s.pending.IsZero() {
		s.pending = principal.SealedFromBytes([]byte("sealed-pending-" + string(s.handle[:4])))
	}
	created := now().Add(-s.age).Truncate(time.Microsecond).Add(subMicro)
	if s.expired {
		created = now().Add(-2 * s.kind.TTL()).Truncate(time.Microsecond).Add(subMicro)
	}
	expires := created.Add(s.kind.TTL())
	r, err := restore(ceremony.Row{
		Tenant:     s.tenant,
		Kind:       s.kind,
		HandleHash: s.handle,
		ScopeHash:  s.scope,
		Pending:    s.pending,
		Payload:    s.payload,
		ExpiresAt:  expires,
		CreatedAt:  created,
	})
	require.NoError(t, err)
	return r
}

func put(t *testing.T, s ceremony.Store, r ceremony.Record) int {
	t.Helper()
	n, err := s.Put(context.Background(), r)
	require.NoError(t, err)
	return n
}

func live(s ceremony.Store, r ceremony.Record) bool {
	_, err := s.Peek(context.Background(), r.Tenant(), r.Kind(), r.HandleHash())
	return err == nil
}

func baseSuite(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	require.NoError(t, s.Ping(ctx))
	require.True(t, s.Durability().Valid())

	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	ra := build(t, rs, spec{tenant: a, kind: ceremony.MFAFlow})
	rb := build(t, rs, spec{tenant: b, kind: ceremony.MFAFlow})
	rz := build(t, rs, spec{kind: ceremony.MFAFlow})
	for _, r := range []ceremony.Record{ra, rb, rz} {
		put(t, s, r)
	}
	first, err := s.MarkConsumed(ctx, a, ceremony.OAuthState, handle(), now().Add(time.Hour))
	require.NoError(t, err)
	require.True(t, first)

	require.NoError(t, s.EraseTenant(ctx, a))
	require.False(t, live(s, ra))
	require.True(t, live(s, rb))
	require.True(t, live(s, rz))
	require.NoError(t, s.EraseTenant(ctx, a))
}

func roundTrip(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	r := build(t, rs, spec{tenant: tenant(t, "t"), kind: ceremony.EmailCode, payload: []byte("payload")})
	require.Zero(t, put(t, s, r))
	got, err := s.Peek(ctx, r.Tenant(), r.Kind(), r.HandleHash())
	require.NoError(t, err)
	require.Equal(t, r.Tenant(), got.Tenant())
	require.Equal(t, r.Kind(), got.Kind())
	require.Equal(t, r.HandleHash(), got.HandleHash())
	require.Equal(t, r.ScopeHash(), got.ScopeHash())
	require.Equal(t, r.Payload(), got.Payload())
	require.Equal(t, r.Pending.Bytes(), got.Pending.Bytes())
	require.Zero(t, got.Attempts())
	require.Equal(t, subMicro, time.Duration(r.CreatedAt().Nanosecond()%1000))
	require.True(t, r.ExpiresAt().Truncate(time.Microsecond).Equal(got.ExpiresAt()), "stores keep instants to the microsecond")
	require.True(t, r.CreatedAt().Truncate(time.Microsecond).Equal(got.CreatedAt()), "stores keep instants to the microsecond")
	require.NoError(t, got.Validate())

	again, err := s.Peek(ctx, r.Tenant(), r.Kind(), r.HandleHash())
	require.NoError(t, err)
	require.Equal(t, got.HandleHash(), again.HandleHash())

	consumed, err := s.Consume(ctx, r.Tenant(), r.Kind(), r.HandleHash())
	require.NoError(t, err)
	require.Equal(t, r.Payload(), consumed.Payload())
	_, err = s.Peek(ctx, r.Tenant(), r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func fullPendingRoundTrip(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	want := principaltest.FullPending()
	sealed, err := core.SealPending(want)
	require.NoError(t, err)
	subject, bound := want.Subject()
	require.True(t, bound)
	r := build(t, rs, spec{tenant: want.Tenant(), kind: ceremony.MFAFlow, scope: subject.User[:], pending: sealed})
	put(t, s, r)
	for _, read := range []func(context.Context, principal.TenantID, ceremony.Kind, []byte) (ceremony.Record, error){s.Peek, s.Consume} {
		got, err := read(ctx, r.Tenant(), r.Kind(), r.HandleHash())
		require.NoError(t, err)
		require.Equal(t, sealed.Bytes(), got.Pending.Bytes())
		back, err := core.UnsealPending(principal.SealedFromBytes(got.Pending.Bytes()))
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(want, back), "round trip differs:\n%#v\n%#v", want, back)
	}
}

func putRefusals(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	_, err := s.Put(ctx, ceremony.Record{})
	require.ErrorIs(t, err, ceremony.ErrInvalidRecord)

	r := build(t, rs, spec{kind: ceremony.MFAFlow})
	r.Pending = principal.SealedFromBytes([]byte("replaced"))
	_, err = s.Put(ctx, r)
	require.ErrorIs(t, err, ceremony.ErrInvalidRecord)
	require.False(t, live(s, r))

	dup := build(t, rs, spec{kind: ceremony.MFAFlow})
	put(t, s, dup)
	_, err = s.Put(ctx, dup)
	require.ErrorIs(t, err, store.ErrConflict)
	other := build(t, rs, spec{kind: ceremony.MFAFlow, handle: dup.HandleHash()})
	_, err = s.Put(ctx, other)
	require.ErrorIs(t, err, store.ErrConflict)
	otherKind := build(t, rs, spec{kind: ceremony.MFAPasskey, handle: dup.HandleHash()})
	put(t, s, otherKind)

	gone := build(t, rs, spec{kind: ceremony.MFAFlow, expired: true})
	put(t, s, gone)
	require.False(t, live(s, gone))
	_, err = s.Consume(ctx, gone.Tenant(), gone.Kind(), gone.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	reused := build(t, rs, spec{kind: ceremony.MFAFlow, handle: gone.HandleHash()})
	put(t, s, reused)
	require.True(t, live(s, reused))
}

func isolation(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	r := build(t, rs, spec{tenant: a, kind: ceremony.EmailCode})
	put(t, s, r)

	_, err := s.Peek(ctx, b, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Consume(ctx, b, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.RecordFailure(ctx, b, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Peek(ctx, r.Tenant(), ceremony.SMSCode, r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Peek(ctx, principal.TenantID{}, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)

	got, err := s.Peek(ctx, a, r.Kind(), r.HandleHash())
	require.NoError(t, err)
	require.Zero(t, got.Attempts())

	n, err := s.DeleteForScope(ctx, b, r.ScopeHash())
	require.NoError(t, err)
	require.Zero(t, n)
	require.True(t, live(s, r))

	_, err = s.Peek(ctx, a, ceremony.OAuthState, r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)

	shared := handle()
	ra := build(t, rs, spec{tenant: a, kind: ceremony.MFAFlow, handle: shared})
	rb := build(t, rs, spec{tenant: b, kind: ceremony.MFAFlow, handle: shared})
	put(t, s, ra)
	put(t, s, rb)
	_, err = s.Consume(ctx, a, ceremony.MFAFlow, shared)
	require.NoError(t, err)
	require.True(t, live(s, rb))
}

func consumeSingleUse(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	r := build(t, rs, spec{tenant: tenant(t, "t"), kind: ceremony.MagicLink})
	put(t, s, r)

	var wins, misses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		wg.Go(func() {
			<-start
			_, err := s.Consume(ctx, r.Tenant(), r.Kind(), r.HandleHash())
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrNotFound):
				misses.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
	require.EqualValues(t, goroutines-1, misses.Load())
}

func markConsumed(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	h := handle()
	until := now().Add(time.Hour)

	var firsts atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		wg.Go(func() {
			<-start
			first, err := s.MarkConsumed(ctx, a, ceremony.OAuthState, h, until)
			if err == nil && first {
				firsts.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, firsts.Load())

	first, err := s.MarkConsumed(ctx, a, ceremony.OAuthState, h, until)
	require.NoError(t, err)
	require.False(t, first)
	first, err = s.MarkConsumed(ctx, b, ceremony.OAuthState, h, until)
	require.NoError(t, err)
	require.True(t, first, "tenants never share a mark")
	first, err = s.MarkConsumed(ctx, a, ceremony.ExternalLogin, h, until)
	require.NoError(t, err)
	require.True(t, first, "kinds never share a mark")

	lapsed := handle()
	past := now().Add(-time.Minute)
	first, err = s.MarkConsumed(ctx, a, ceremony.OAuthState, lapsed, past)
	require.NoError(t, err)
	require.True(t, first)
	first, err = s.MarkConsumed(ctx, a, ceremony.OAuthState, lapsed, until)
	require.NoError(t, err)
	require.True(t, first, "a lapsed mark no longer blocks")

	_, err = s.MarkConsumed(ctx, a, ceremony.MFAFlow, handle(), until)
	require.ErrorIs(t, err, ceremony.ErrStoredKind)
	_, err = s.MarkConsumed(ctx, a, ceremony.OAuthState, handle()[:8], until)
	require.ErrorIs(t, err, ceremony.ErrHandleTooShort)

	require.NoError(t, s.EraseTenant(ctx, a))
	first, err = s.MarkConsumed(ctx, a, ceremony.OAuthState, h, until)
	require.NoError(t, err)
	require.True(t, first, "EraseTenant removes the marks")
}

func evictionPerScope(t *testing.T, s ceremony.Store, rs Restorer) {
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	kind := ceremony.MFAFlow
	maxLive := kind.MaxLivePerScope()
	scopeA, scopeB := userScope(), userScope()

	var inA []ceremony.Record
	for i := range maxLive {
		r := build(t, rs, spec{tenant: a, kind: kind, scope: scopeA, age: time.Duration(maxLive-i) * time.Second})
		require.Zero(t, put(t, s, r))
		inA = append(inA, r)
	}
	bystanders := []ceremony.Record{
		build(t, rs, spec{tenant: a, kind: kind, scope: scopeB}),
		build(t, rs, spec{tenant: b, kind: kind, scope: scopeA}),
		build(t, rs, spec{tenant: a, kind: ceremony.MFAPasskey, scope: scopeA}),
	}
	for _, r := range bystanders {
		require.Zero(t, put(t, s, r))
	}

	newest := build(t, rs, spec{tenant: a, kind: kind, scope: scopeA})
	require.Equal(t, 1, put(t, s, newest))
	require.False(t, live(s, inA[0]), "oldest record is evicted first")
	for _, r := range append(inA[1:], newest) {
		require.True(t, live(s, r))
	}
	for _, r := range bystanders {
		require.True(t, live(s, r), "another scope, tenant or kind is never evicted")
	}

	for range maxLive {
		put(t, s, build(t, rs, spec{tenant: a, kind: kind, scope: scopeA}))
	}
	for _, r := range bystanders {
		require.True(t, live(s, r))
	}

	lapsed := build(t, rs, spec{tenant: a, kind: ceremony.MagicLink, expired: true})
	scope := lapsed.ScopeHash()
	require.Zero(t, put(t, s, lapsed))
	for range ceremony.MagicLink.MaxLivePerScope() {
		require.Zero(t, put(t, s, build(t, rs, spec{tenant: a, kind: ceremony.MagicLink, scope: scope})), "expired records never count toward the cap")
	}
}

func evictionConcurrent(t *testing.T, s ceremony.Store, rs Restorer) {
	a := tenant(t, "tenant-a")
	kind := ceremony.MFAFlow
	scope := userScope()
	recs := make([]ceremony.Record, goroutines)
	for i := range recs {
		recs[i] = build(t, rs, spec{tenant: a, kind: kind, scope: scope, age: time.Duration(goroutines-i) * time.Millisecond})
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, r := range recs {
		wg.Go(func() {
			<-start
			_, _ = s.Put(context.Background(), r)
		})
	}
	close(start)
	wg.Wait()
	liveCount := 0
	for _, r := range recs {
		if live(s, r) {
			liveCount++
		}
	}
	require.Equal(t, kind.MaxLivePerScope(), liveCount, "concurrent Put calls never overshoot the cap")
}

func identifierCeiling(t *testing.T, s ceremony.Store, rs Restorer) {
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	kind := ceremony.PendingRegistration
	ceiling := kind.MaxLivePerTenant()
	require.Positive(t, ceiling)

	require.Less(t, 30*time.Second, kind.TTL()-time.Minute, "the records must outlive a slow insert of the whole ceiling")
	guard := build(t, rs, spec{tenant: b, kind: kind, age: 31 * time.Second})
	require.Zero(t, put(t, s, guard))
	oldest := build(t, rs, spec{tenant: a, kind: kind, age: 31 * time.Second})
	require.Zero(t, put(t, s, oldest))
	var all []ceremony.Record
	for i := 1; i < ceiling; i++ {
		r := build(t, rs, spec{tenant: a, kind: kind, age: 30*time.Second - time.Duration(i)*time.Millisecond})
		require.Zero(t, put(t, s, r))
		all = append(all, r)
	}
	require.True(t, live(s, oldest))

	extra := build(t, rs, spec{tenant: a, kind: kind})
	require.Equal(t, 1, put(t, s, extra))
	require.False(t, live(s, oldest), "the oldest record of the tenant is evicted past the ceiling")
	require.True(t, live(s, all[0]))
	require.True(t, live(s, extra))
	require.True(t, live(s, guard), "another tenant never counts toward the ceiling")
}

func shortHandles(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a := tenant(t, "t")
	for _, kind := range []ceremony.Kind{ceremony.EmailCode, ceremony.SMSCode, ceremony.PhoneVerification} {
		short := []byte("123456")
		_, err := rs(ceremony.Row{Tenant: a, Kind: kind, HandleHash: short, ScopeHash: scopeFor(kind), Pending: principal.SealedFromBytes([]byte("p")), CreatedAt: now(), ExpiresAt: now().Add(time.Minute)})
		require.ErrorIs(t, err, ceremony.ErrHandleTooShort)
		_, err = s.Peek(ctx, a, kind, short)
		require.ErrorIs(t, err, ceremony.ErrHandleTooShort)
		_, err = s.Consume(ctx, a, kind, short)
		require.ErrorIs(t, err, ceremony.ErrHandleTooShort)
		_, err = s.RecordFailure(ctx, a, kind, short)
		require.ErrorIs(t, err, ceremony.ErrHandleTooShort)
	}
	_, err := s.Peek(ctx, a, ceremony.EmailCode, nil)
	require.ErrorIs(t, err, ceremony.ErrHandleTooShort)
}

func attempts(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a := tenant(t, "t")
	r := build(t, rs, spec{tenant: a, kind: ceremony.EmailCode})
	put(t, s, r)
	maxAttempts := r.Kind().MaxAttempts()

	for i := 1; i < maxAttempts; i++ {
		remaining, err := s.RecordFailure(ctx, a, r.Kind(), r.HandleHash())
		require.NoError(t, err)
		require.Equal(t, maxAttempts-i, remaining)
		got, err := s.Peek(ctx, a, r.Kind(), r.HandleHash())
		require.NoError(t, err)
		require.Equal(t, i, got.Attempts())
	}
	remaining, err := s.RecordFailure(ctx, a, r.Kind(), r.HandleHash())
	require.NoError(t, err)
	require.Zero(t, remaining)
	_, err = s.Peek(ctx, a, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound, "the record is deleted at zero remaining")
	_, err = s.RecordFailure(ctx, a, r.Kind(), r.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)

	gone := build(t, rs, spec{tenant: a, kind: ceremony.EmailCode, expired: true})
	put(t, s, gone)
	_, err = s.RecordFailure(ctx, a, gone.Kind(), gone.HandleHash())
	require.ErrorIs(t, err, store.ErrNotFound)

	var wg sync.WaitGroup
	conc := build(t, rs, spec{tenant: a, kind: ceremony.EmailCode})
	put(t, s, conc)
	var zeros atomic.Int32
	for range goroutines {
		wg.Go(func() {
			if rem, err := s.RecordFailure(ctx, a, conc.Kind(), conc.HandleHash()); err == nil && rem == 0 {
				zeros.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, zeros.Load(), "exactly one failure takes the last attempt")
	require.False(t, live(s, conc))
}

func deleteForScope(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	scope := userScope()
	r1 := build(t, rs, spec{tenant: a, kind: ceremony.MFAFlow, scope: scope})
	r2 := build(t, rs, spec{tenant: a, kind: ceremony.MFAPasskey, scope: scope})
	r3 := build(t, rs, spec{tenant: a, kind: ceremony.PasswordReset, scope: scope})
	otherScope := build(t, rs, spec{tenant: a, kind: ceremony.MFAFlow})
	otherTenant := build(t, rs, spec{tenant: b, kind: ceremony.MFAFlow, scope: scope})
	for _, r := range []ceremony.Record{r1, r2, r3, otherScope, otherTenant} {
		put(t, s, r)
	}

	n, err := s.DeleteForScope(ctx, a, scope, ceremony.MFAFlow, ceremony.MFAPasskey)
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
	require.False(t, live(s, r1))
	require.False(t, live(s, r2))
	require.True(t, live(s, r3))

	n, err = s.DeleteForScope(ctx, a, scope)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	require.False(t, live(s, r3))
	require.True(t, live(s, otherScope))
	require.True(t, live(s, otherTenant))

	n, err = s.DeleteForScope(ctx, a, scope)
	require.NoError(t, err)
	require.Zero(t, n)
}

func reapExpired(t *testing.T, s ceremony.Store, rs Restorer) {
	ctx := context.Background()
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	deadA := build(t, rs, spec{tenant: a, kind: ceremony.MagicLink, expired: true})
	deadB := build(t, rs, spec{tenant: b, kind: ceremony.EmailCode, expired: true})
	deadZ := build(t, rs, spec{kind: ceremony.Exchange, expired: true})
	liveA := build(t, rs, spec{tenant: a, kind: ceremony.MagicLink})
	liveB := build(t, rs, spec{tenant: b, kind: ceremony.EmailCode})
	for _, r := range []ceremony.Record{deadA, deadB, deadZ, liveA, liveB} {
		put(t, s, r)
	}
	n, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	require.True(t, live(s, liveA))
	require.True(t, live(s, liveB))

	n, err = s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)

	h := handle()
	first, err := s.MarkConsumed(ctx, a, ceremony.OAuthState, h, now().Add(-time.Minute))
	require.NoError(t, err)
	require.True(t, first)
	n, err = s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "lapsed single-use marks are reaped too")
}
