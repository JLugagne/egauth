// Package storetest holds the conformance suite of sessions.Store implementations.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/JLugagne/egauth/store/sessions"
)

const goroutines = 16

// Fixtures is what the store implementation's test hands the suite through Seed.
type Fixtures struct {
	// Restore is sessions.Restore: the suite builds its records with it but may not call it itself
	// (G6).
	Restore func(sessions.Row) (sessions.Record, error)
	// Travel moves the clock of s by d for every later call. A store whose clock is the database's
	// may instead shift every instant it already holds by -d: both make earlier writes look d older.
	Travel func(t *testing.T, s sessions.Store, d time.Duration)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the sessions.Store contract against stores returned by newStore. Each subtest gets
// a fresh store. Records are built with wall-clock instants truncated to the microsecond, the
// precision every store keeps. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) sessions.Store) {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, Fixtures{...}) before Run")
	}
	f := v.(Fixtures)
	if f.Restore == nil || f.Travel == nil {
		t.Fatal("storetest: Fixtures.Restore and Fixtures.Travel are required")
	}
	suites := map[string]func(*testing.T, *harness){
		"Base":                 baseSuite,
		"FullRoundTrip":        fullRoundTrip,
		"CreateRefusals":       createRefusals,
		"GetStates":            getStates,
		"Touch":                touch,
		"TouchAfterRotate":     touchAfterRotate,
		"Rotate":               rotate,
		"RotateRefusals":       rotateRefusals,
		"RotateConcurrent":     rotateConcurrent,
		"Replace":              replace,
		"ReplaceRefusals":      replaceRefusals,
		"ReplaceConcurrent":    replaceConcurrent,
		"Revoke":               revoke,
		"RevokeSession":        revokeSession,
		"RevokeForSubject":     revokeForSubject,
		"RevocationsBackdated": revocationsBackdated,
		"DeleteForSubject":     deleteForSubject,
		"ReapExpired":          reapExpired,
		"SingleTenant":         singleTenant,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, &harness{t: t, s: newStore(t), f: f}) })
	}
}

type harness struct {
	t *testing.T
	s sessions.Store
	f Fixtures
}

var counter atomic.Uint64

func now() time.Time { return clock.Clock{}.Now().UTC().Truncate(time.Microsecond) }

func digest() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter.Add(1))
	sum := sha256.Sum256(append([]byte("sessions-storetest"), b[:]...))
	return sum[:]
}

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	require.NoError(t, err)
	return id
}

func subject(t *testing.T, tn string) principal.Subject {
	return principal.Subject{Tenant: tenant(t, tn), User: uuid.New()}
}

type spec struct {
	id      uuid.UUID
	subject principal.Subject
	lineage uuid.UUID
	hash    []byte
	fp      []byte
	sealed  principal.Sealed
	claims  []byte
	epoch   uint64
	created time.Time
	checked time.Time
	idle    time.Duration
	life    time.Duration
}

func (h *harness) build(s spec) sessions.Record {
	h.t.Helper()
	if s.id == uuid.Nil {
		s.id = uuid.New()
	}
	if s.lineage == uuid.Nil {
		s.lineage = uuid.New()
	}
	if s.hash == nil {
		s.hash = digest()
	}
	if s.sealed.IsZero() {
		s.sealed = principal.SealedFromBytes(append([]byte("sealed-attrs-"), s.hash[:6]...))
	}
	if s.created.IsZero() {
		s.created = now()
	}
	if s.checked.IsZero() {
		s.checked = s.created
	}
	if s.idle == 0 {
		s.idle = time.Hour
	}
	if s.life == 0 {
		s.life = 24 * time.Hour
	}
	end := s.created.Add(s.life)
	idle := s.checked.Add(s.idle)
	if idle.After(end) {
		idle = end
	}
	r, err := h.f.Restore(sessions.Row{
		ID:                s.id,
		TokenHash:         s.hash,
		Subject:           s.subject,
		Lineage:           s.lineage,
		Sealed:            s.sealed,
		AppClaims:         s.claims,
		SecurityEpoch:     s.epoch,
		ClientFingerprint: s.fp,
		IdleExpiresAt:     idle,
		AbsoluteExpiresAt: end,
		CheckedAt:         s.checked,
		CreatedAt:         s.created,
	})
	require.NoError(h.t, err)
	return r
}

func (h *harness) create(s spec) sessions.Record {
	h.t.Helper()
	r := h.build(s)
	require.NoError(h.t, h.s.Create(context.Background(), r))
	return r
}

func (h *harness) renewed(of sessions.Record) sessions.Record {
	h.t.Helper()
	return h.build(spec{
		id: of.ID(), subject: of.Subject(), lineage: of.Lineage(), created: of.CreatedAt(), checked: now(),
		claims: []byte("renewed-claims"), epoch: of.Epoch() + 1, fp: []byte("renewed-fp"),
		life: of.AbsoluteExpiresAt().Sub(of.CreatedAt()),
	})
}

func (h *harness) successor(of sessions.Record) sessions.Record {
	h.t.Helper()
	return h.build(spec{subject: of.Subject(), lineage: of.Lineage(), claims: []byte("successor")})
}

func (h *harness) live(r sessions.Record) bool {
	h.t.Helper()
	_, err := h.s.Get(context.Background(), r.Tenant(), r.TokenHash())
	if err != nil {
		require.ErrorIs(h.t, err, store.ErrNotFound)
	}
	return err == nil
}

func (h *harness) feed(c store.Cursor) ([]sessions.Revocation, store.Cursor) {
	h.t.Helper()
	revs, next, err := h.s.RevocationsSince(context.Background(), c)
	require.NoError(h.t, err)
	require.False(h.t, c.After(next), "the cursor never moves backwards")
	return revs, next
}

func (h *harness) head() store.Cursor {
	h.t.Helper()
	_, c := h.feed(store.Cursor{})
	return c
}

func (h *harness) requireRecord(want, got sessions.Record) {
	h.t.Helper()
	require.True(h.t, reflect.DeepEqual(want, got), "record differs after the round trip:\nwant %#v\ngot  %#v", want, got)
}

func ids(revs []sessions.Revocation) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(revs))
	for _, r := range revs {
		out = append(out, r.Session)
	}
	return out
}

func baseSuite(t *testing.T, h *harness) {
	ctx := context.Background()
	require.NoError(t, h.s.Ping(ctx))
	require.True(t, h.s.Durability().Valid())

	sa, sb := subject(t, "tenant-a"), subject(t, "tenant-b")
	ra := h.create(spec{subject: sa})
	rb := h.create(spec{subject: sb})
	c := h.head()
	require.NoError(t, h.s.EraseTenant(ctx, sa.Tenant))
	require.False(t, h.live(ra))
	require.True(t, h.live(rb))
	revs, _ := h.feed(c)
	require.Equal(t, []uuid.UUID{ra.ID()}, ids(revs), "erased sessions are announced on the feed")
	require.Equal(t, sa.Tenant, revs[0].Tenant)
	require.NoError(t, h.s.EraseTenant(ctx, sa.Tenant))
	revs, _ = h.feed(c)
	require.Len(t, revs, 1)
}

func fullRoundTrip(t *testing.T, h *harness) {
	ctx := context.Background()
	full := principaltest.Full()
	sealed, err := core.Seal(full)
	require.NoError(t, err)
	r := h.create(spec{
		subject: full.Subject(), lineage: full.Lineage(), sealed: sealed, epoch: full.Epoch(),
		claims: []byte(`{"roles":["admin"]}`), fp: []byte("fingerprint"),
	})
	got, err := h.s.Get(ctx, r.Tenant(), r.TokenHash())
	require.NoError(t, err)
	h.requireRecord(r, got)
	require.True(t, reflect.DeepEqual(sealed, got.Sealed()), "the sealed attributes must come back byte for byte")

	next := h.renewed(r)
	require.NoError(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash(), Next: next}))
	got, err = h.s.Get(ctx, next.Tenant(), next.TokenHash())
	require.NoError(t, err)
	h.requireRecord(next, got)
}

func createRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	require.ErrorIs(t, h.s.Create(ctx, sessions.Record{}), sessions.ErrInvalidRecord)
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	require.ErrorIs(t, h.s.Create(ctx, r), store.ErrConflict)
	sameID := h.build(spec{id: r.ID(), subject: s})
	require.ErrorIs(t, h.s.Create(ctx, sameID), store.ErrConflict, "a duplicate id")
	require.False(t, h.live(sameID))
	sameHash := h.build(spec{subject: s, hash: r.TokenHash()})
	require.ErrorIs(t, h.s.Create(ctx, sameHash), store.ErrConflict, "a duplicate token digest")
	got, err := h.s.Get(ctx, s.Tenant, r.TokenHash())
	require.NoError(t, err)
	h.requireRecord(r, got)
}

func getStates(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	_, err := h.s.Get(ctx, tenant(t, "other"), r.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound, "a session is invisible from another tenant")
	_, err = h.s.Get(ctx, s.Tenant, digest())
	require.ErrorIs(t, err, store.ErrNotFound)
	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	require.False(t, h.live(idle), "an idle-expired session is not found")
	ended := h.create(spec{subject: s, created: now().Add(-3 * time.Hour), idle: 5 * time.Hour, life: 2 * time.Hour})
	require.False(t, h.live(ended), "an ended session is not found")
}

func touch(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s, idle: time.Hour, life: 3 * time.Hour})

	got, err := h.s.Touch(ctx, s.Tenant, r.TokenHash(), r.IdleExpiresAt().Add(30*time.Minute))
	require.NoError(t, err)
	require.True(t, r.IdleExpiresAt().Add(30*time.Minute).Equal(got))

	kept, err := h.s.Touch(ctx, s.Tenant, r.TokenHash(), r.IdleExpiresAt())
	require.NoError(t, err)
	require.True(t, got.Equal(kept), "Touch never shortens the idle expiry")

	clamped, err := h.s.Touch(ctx, s.Tenant, r.TokenHash(), r.AbsoluteExpiresAt().Add(time.Hour))
	require.NoError(t, err)
	require.True(t, r.AbsoluteExpiresAt().Equal(clamped), "Touch never passes the absolute expiry")
	stored, err := h.s.Get(ctx, s.Tenant, r.TokenHash())
	require.NoError(t, err)
	require.True(t, clamped.Equal(stored.IdleExpiresAt()))

	_, err = h.s.Touch(ctx, tenant(t, "other"), r.TokenHash(), r.AbsoluteExpiresAt())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.Touch(ctx, s.Tenant, digest(), r.AbsoluteExpiresAt())
	require.ErrorIs(t, err, store.ErrNotFound)
	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	_, err = h.s.Touch(ctx, s.Tenant, idle.TokenHash(), now().Add(time.Hour))
	require.ErrorIs(t, err, store.ErrNotFound, "an idle-expired session cannot be revived")
	require.False(t, h.live(idle))
}

func touchAfterRotate(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	next := h.renewed(r)
	require.NoError(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash(), Next: next}))
	_, err := h.s.Touch(ctx, s.Tenant, r.TokenHash(), r.AbsoluteExpiresAt())
	require.ErrorIs(t, err, store.ErrNotFound, "a touch through the old digest never undoes a rotation")
	got, err := h.s.Get(ctx, s.Tenant, next.TokenHash())
	require.NoError(t, err)
	h.requireRecord(next, got)
}

func rotate(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s, created: now().Add(-time.Minute)})
	next := h.renewed(r)
	require.NoError(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash(), Next: next}))
	require.False(t, h.live(r))
	got, err := h.s.Get(ctx, s.Tenant, next.TokenHash())
	require.NoError(t, err)
	require.Equal(t, r.ID(), got.ID())
	require.True(t, r.CreatedAt().Equal(got.CreatedAt()), "rotation keeps the creation time")
	require.Equal(t, next.AppClaims(), got.AppClaims())
	require.Equal(t, next.Epoch(), got.Epoch())
	require.Equal(t, next.ClientFingerprint(), got.ClientFingerprint())
	require.True(t, next.CheckedAt().Equal(got.CheckedAt()))
	require.True(t, next.IdleExpiresAt().Equal(got.IdleExpiresAt()))
}

func rotateRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	other := h.create(spec{subject: s})
	require.ErrorIs(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash()}), sessions.ErrInvalidRecord)
	for name, req := range map[string]sessions.RotateRequest{
		"unknown":   {Previous: digest(), Next: h.renewed(r)},
		"id":        {Previous: r.TokenHash(), Next: h.build(spec{subject: s, lineage: r.Lineage(), created: r.CreatedAt()})},
		"subject":   {Previous: r.TokenHash(), Next: h.build(spec{id: r.ID(), subject: subject(t, "t"), lineage: r.Lineage()})},
		"tenant":    {Previous: r.TokenHash(), Next: h.build(spec{id: r.ID(), subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}, lineage: r.Lineage()})},
		"lineage":   {Previous: r.TokenHash(), Next: h.build(spec{id: r.ID(), subject: s})},
		"collision": {Previous: r.TokenHash(), Next: h.build(spec{id: r.ID(), subject: s, lineage: r.Lineage(), hash: other.TokenHash()})},
		"extended": {Previous: r.TokenHash(), Next: h.build(spec{id: r.ID(), subject: s, lineage: r.Lineage(), created: r.CreatedAt(),
			checked: now(), life: r.AbsoluteExpiresAt().Sub(r.CreatedAt()) + time.Hour})},
	} {
		require.ErrorIs(t, h.s.Rotate(ctx, req), store.ErrConflict, name)
		got, err := h.s.Get(ctx, s.Tenant, r.TokenHash())
		require.NoError(t, err, name)
		h.requireRecord(r, got)
	}
	require.True(t, h.live(other))
	shortened := h.build(spec{id: r.ID(), subject: s, lineage: r.Lineage(), created: r.CreatedAt(), checked: now(),
		life: r.AbsoluteExpiresAt().Sub(r.CreatedAt()) - time.Hour})
	require.NoError(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash(), Next: shortened}),
		"a renewal may shorten the absolute expiry")
	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	require.ErrorIs(t, h.s.Rotate(ctx, sessions.RotateRequest{Previous: idle.TokenHash(), Next: h.renewed(idle)}), store.ErrConflict,
		"an idle-expired session cannot be rotated")
}

func rotateConcurrent(t *testing.T, h *harness) {
	ctx := context.Background()
	r := h.create(spec{subject: subject(t, "t")})
	nexts := make([]sessions.Record, goroutines)
	for i := range nexts {
		nexts[i] = h.renewed(r)
	}
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() { errs[i] = h.s.Rotate(ctx, sessions.RotateRequest{Previous: r.TokenHash(), Next: nexts[i]}) })
	}
	wg.Wait()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
			require.True(t, h.live(nexts[i]))
			continue
		}
		require.ErrorIs(t, err, store.ErrConflict)
		require.False(t, h.live(nexts[i]))
	}
	require.Equal(t, 1, ok, "one rotation wins the compare-and-swap")
}

func replace(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	c0 := h.head()
	next := h.successor(r)
	require.NoError(t, h.s.Replace(ctx, sessions.ReplaceRequest{Previous: r.ID(), Next: next}))
	require.False(t, h.live(r))
	got, err := h.s.Get(ctx, s.Tenant, next.TokenHash())
	require.NoError(t, err)
	h.requireRecord(next, got)
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{r.ID()}, ids(revs))

	again := h.successor(r)
	require.ErrorIs(t, h.s.Replace(ctx, sessions.ReplaceRequest{Previous: r.ID(), Next: again}), store.ErrConflict, "the old row is gone")
	require.False(t, h.live(again))
}

func replaceRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	other := h.create(spec{subject: s})
	require.ErrorIs(t, h.s.Replace(ctx, sessions.ReplaceRequest{Previous: r.ID()}), sessions.ErrInvalidRecord)
	for name, req := range map[string]sessions.ReplaceRequest{
		"unknown":    {Previous: uuid.New(), Next: h.successor(r)},
		"same id":    {Previous: r.ID(), Next: h.build(spec{id: r.ID(), subject: s, lineage: r.Lineage()})},
		"subject":    {Previous: r.ID(), Next: h.build(spec{subject: subject(t, "t"), lineage: r.Lineage()})},
		"tenant":     {Previous: r.ID(), Next: h.build(spec{subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}, lineage: r.Lineage()})},
		"lineage":    {Previous: r.ID(), Next: h.build(spec{subject: s})},
		"id taken":   {Previous: r.ID(), Next: h.build(spec{id: other.ID(), subject: s, lineage: r.Lineage()})},
		"hash taken": {Previous: r.ID(), Next: h.build(spec{subject: s, lineage: r.Lineage(), hash: other.TokenHash()})},
	} {
		c := h.head()
		require.ErrorIs(t, h.s.Replace(ctx, req), store.ErrConflict, name)
		require.True(t, h.live(r), "a refused replace revokes nothing (%s)", name)
		revs, _ := h.feed(c)
		require.Empty(t, revs, name)
	}
	require.True(t, h.live(other))
	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	require.ErrorIs(t, h.s.Replace(ctx, sessions.ReplaceRequest{Previous: idle.ID(), Next: h.successor(idle)}), store.ErrConflict,
		"an idle-expired session cannot be replaced")
}

func replaceConcurrent(t *testing.T, h *harness) {
	ctx := context.Background()
	r := h.create(spec{subject: subject(t, "t")})
	nexts := make([]sessions.Record, goroutines)
	for i := range nexts {
		nexts[i] = h.successor(r)
	}
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() { errs[i] = h.s.Replace(ctx, sessions.ReplaceRequest{Previous: r.ID(), Next: nexts[i]}) })
	}
	wg.Wait()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, store.ErrConflict)
		require.False(t, h.live(nexts[i]))
	}
	require.Equal(t, 1, ok)
}

func revoke(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	c0 := h.head()
	require.NoError(t, h.s.Revoke(ctx, tenant(t, "other"), r.TokenHash()))
	require.True(t, h.live(r), "another tenant cannot revoke the session")
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, r.TokenHash()))
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, r.TokenHash()))
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, digest()))
	require.False(t, h.live(r))
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{r.ID()}, ids(revs), "revocation is idempotent")
	require.Equal(t, s.Tenant, revs[0].Tenant)
	require.False(t, revs[0].At.IsZero())
}

func revokeSession(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	stranger := subject(t, "t")
	c0 := h.head()
	require.NoError(t, h.s.RevokeSession(ctx, stranger, r.ID()))
	require.NoError(t, h.s.RevokeSession(ctx, principal.Subject{Tenant: tenant(t, "other"), User: s.User}, r.ID()))
	require.True(t, h.live(r), "a row of another subject or tenant is never touched")
	require.NoError(t, h.s.RevokeSession(ctx, s, r.ID()))
	require.NoError(t, h.s.RevokeSession(ctx, s, r.ID()))
	require.False(t, h.live(r))
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{r.ID()}, ids(revs))
}

func revokeForSubject(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	keep := uuid.New()
	l1 := h.create(spec{subject: s})
	l2 := h.create(spec{subject: s, lineage: keep})
	l3 := h.create(spec{subject: s})
	neighbour := h.create(spec{subject: subject(t, "t")})
	twin := h.create(spec{subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}})
	c0 := h.head()

	require.NoError(t, h.s.RevokeForSubject(ctx, s, keep))
	require.False(t, h.live(l1))
	require.True(t, h.live(l2), "the kept lineage survives")
	require.False(t, h.live(l3))
	require.True(t, h.live(neighbour))
	require.True(t, h.live(twin), "the same user id in another tenant is another subject")
	revs, c1 := h.feed(c0)
	require.ElementsMatch(t, []uuid.UUID{l1.ID(), l3.ID()}, ids(revs))

	require.NoError(t, h.s.RevokeForSubject(ctx, s, keep))
	revs, _ = h.feed(c1)
	require.Empty(t, revs)
	require.NoError(t, h.s.RevokeForSubject(ctx, s, uuid.Nil))
	require.False(t, h.live(l2), "uuid.Nil keeps nothing")
	revs, _ = h.feed(c1)
	require.Equal(t, []uuid.UUID{l2.ID()}, ids(revs))
}

func revocationsBackdated(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s, life: 48 * time.Hour, idle: 4 * time.Hour})
	b := h.create(spec{subject: s, life: 48 * time.Hour, idle: 4 * time.Hour})
	c := h.create(spec{subject: s, life: 48 * time.Hour, idle: 4 * time.Hour})
	start := h.head()
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, a.TokenHash()))
	first, c1 := h.feed(start)
	require.Len(t, first, 1)
	require.True(t, c1.After(start))

	h.f.Travel(t, h.s, -time.Hour)
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, b.TokenHash()))
	second, c2 := h.feed(c1)
	require.Equal(t, []uuid.UUID{b.ID()}, ids(second), "a back-dated revocation is still returned after the cursor")
	both, _ := h.feed(start)
	require.Len(t, both, 2)
	require.True(t, both[1].At.Before(both[0].At), "the second revocation is stamped earlier than the first")
	require.True(t, c2.After(c1))

	none, c3 := h.feed(c2)
	require.Empty(t, none)
	require.Equal(t, c2, c3, "an empty read keeps the cursor")

	require.NoError(t, h.s.Revoke(ctx, s.Tenant, c.TokenHash()))
	all, _ := h.feed(start)
	require.Equal(t, []uuid.UUID{a.ID(), b.ID(), c.ID()}, ids(all), "oldest first in feed order")
}

func deleteForSubject(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	b := h.create(spec{subject: s})
	other := h.create(spec{subject: subject(t, "t")})
	twin := h.create(spec{subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}})
	require.NoError(t, h.s.DeleteForSubject(ctx, s))
	require.False(t, h.live(a))
	require.False(t, h.live(b))
	require.True(t, h.live(other))
	require.True(t, h.live(twin))
	require.NoError(t, h.s.DeleteForSubject(ctx, s))
}

func reapExpired(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	live := h.create(spec{subject: s})
	h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	h.create(spec{subject: s, created: now().Add(-3 * time.Hour), idle: 5 * time.Hour, life: 2 * time.Hour})
	n, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	require.True(t, h.live(live))
	n, err = h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}

func singleTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	s := principal.Subject{User: uuid.New()}
	r := h.create(spec{subject: s})
	got, err := h.s.Get(ctx, s.Tenant, r.TokenHash())
	require.NoError(t, err, "a session of the single tenant reads back")
	h.requireRecord(r, got)

	c0 := h.head()
	require.NoError(t, h.s.Revoke(ctx, s.Tenant, r.TokenHash()))
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{r.ID()}, ids(revs))
	require.True(t, revs[0].Tenant.IsZero(), "the feed reports the single tenant")
}
