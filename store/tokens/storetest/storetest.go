// Package storetest holds the conformance suite of tokens.Store implementations.
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
	"github.com/JLugagne/egauth/store/tokens"
)

const goroutines = 16

// Fixtures is what the store implementation's test hands the suite through Seed.
type Fixtures struct {
	// Restore is tokens.RestoreRefreshRecord: the suite builds its records with it but may not
	// call it itself (G6).
	Restore func(tokens.RefreshRow) (tokens.RefreshRecord, error)
	// Travel moves the clock of s by d for every later call. A store whose clock is the database's
	// may instead shift every instant it already holds by -d: both make earlier writes look d older.
	Travel func(t *testing.T, s tokens.Store, d time.Duration)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the tokens.Store contract against stores returned by newStore. Each subtest gets a
// fresh store. Records are built with wall-clock instants truncated to the microsecond, the
// precision every store keeps. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) tokens.Store) {
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
		"Base":                     baseSuite,
		"FullRoundTrip":            fullRoundTrip,
		"CreateRefusals":           createRefusals,
		"GetStates":                getStates,
		"Rotate":                   rotate,
		"RotateRefusals":           rotateRefusals,
		"ReuseWithinGraceSameFP":   reuseWithinGrace,
		"ReuseFromOtherClient":     reuseFromOtherClient,
		"ReuseWithoutFingerprint":  reuseWithoutFingerprint,
		"ReuseAfterGraceStoreTime": reuseAfterGrace,
		"GraceIgnoresIssuerClock":  graceIgnoresIssuerClock,
		"RotateConcurrent":         rotateConcurrent,
		"Reissue":                  reissue,
		"ReissueRefusals":          reissueRefusals,
		"ReissueConcurrent":        reissueConcurrent,
		"FamilyState":              familyState,
		"RevokeFamily":             revokeFamily,
		"RevokeForSubject":         revokeForSubject,
		"RevocationsBackdated":     revocationsBackdated,
		"DeleteForSubject":         deleteForSubject,
		"APIKeys":                  apiKeys,
		"APIKeyRefusals":           apiKeyRefusals,
		"APIKeyConcurrentID":       apiKeyConcurrentID,
		"ReapExpired":              reapExpired,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, &harness{t: t, s: newStore(t), f: f}) })
	}
}

type harness struct {
	t *testing.T
	s tokens.Store
	f Fixtures
}

var counter atomic.Uint64

func now() time.Time { return clock.Clock{}.Now().UTC().Truncate(time.Microsecond) }

func digest() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter.Add(1))
	sum := sha256.Sum256(append([]byte("tokens-storetest"), b[:]...))
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
	subject principal.Subject
	lineage uuid.UUID
	family  uuid.UUID
	hash    []byte
	fp      []byte
	sealed  principal.Sealed
	claims  []byte
	epoch   uint64
	created time.Time
	idle    time.Duration
	life    time.Duration
	ends    time.Time
}

func (h *harness) build(s spec) tokens.RefreshRecord {
	h.t.Helper()
	if s.lineage == uuid.Nil {
		s.lineage = uuid.New()
	}
	if s.family == uuid.Nil {
		s.family = uuid.New()
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
	if s.idle == 0 {
		s.idle = time.Hour
	}
	if s.life == 0 {
		s.life = 24 * time.Hour
	}
	familyEnd := s.created.Add(s.life)
	if !s.ends.IsZero() {
		familyEnd = s.ends
	}
	idleEnd := s.created.Add(s.idle)
	if idleEnd.After(familyEnd) {
		idleEnd = familyEnd
	}
	r, err := h.f.Restore(tokens.RefreshRow{
		TokenHash:         s.hash,
		Family:            s.family,
		Subject:           s.subject,
		Lineage:           s.lineage,
		Sealed:            s.sealed,
		AppClaims:         s.claims,
		SecurityEpoch:     s.epoch,
		ClientFingerprint: s.fp,
		IdleExpiresAt:     idleEnd,
		FamilyExpiresAt:   familyEnd,
		CreatedAt:         s.created,
	})
	require.NoError(h.t, err)
	return r
}

func (h *harness) next(of tokens.RefreshRecord, fp []byte) tokens.RefreshRecord {
	h.t.Helper()
	return h.build(spec{subject: of.Subject(), lineage: of.Lineage(), family: of.Family(), fp: fp, epoch: of.Epoch(), ends: of.FamilyExpiresAt()})
}

func (h *harness) create(s spec) tokens.RefreshRecord {
	h.t.Helper()
	r := h.build(s)
	require.NoError(h.t, h.s.Create(context.Background(), r))
	return r
}

func (h *harness) rotate(presented tokens.RefreshRecord, next tokens.RefreshRecord) (tokens.Rotation, error) {
	return h.s.ConsumeForRotation(context.Background(), tokens.RotationRequest{Presented: presented.TokenHash(), Next: next})
}

func (h *harness) feed(c store.Cursor) ([]tokens.Revocation, store.Cursor) {
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

func (h *harness) state(r tokens.RefreshRecord) tokens.FamilyState {
	h.t.Helper()
	st, err := h.s.FamilyState(context.Background(), r.Tenant(), r.Family())
	require.NoError(h.t, err)
	return st
}

func (h *harness) requireRecord(want, got tokens.RefreshRecord) {
	h.t.Helper()
	require.True(h.t, reflect.DeepEqual(want, got), "record differs after the round trip:\nwant %#v\ngot  %#v", want, got)
}

func families(revs []tokens.Revocation) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(revs))
	for _, r := range revs {
		out = append(out, r.Family)
	}
	return out
}

func baseSuite(t *testing.T, h *harness) {
	ctx := context.Background()
	require.NoError(t, h.s.Ping(ctx))
	require.True(t, h.s.Durability().Valid())

	sa, sb := subject(t, "tenant-a"), subject(t, "tenant-b")
	ra := h.create(spec{subject: sa, fp: []byte("fp")})
	rb := h.create(spec{subject: sb})
	ka, kb := apiKey(sa), apiKey(sb)
	require.NoError(t, h.s.CreateAPIKey(ctx, ka))
	require.NoError(t, h.s.CreateAPIKey(ctx, kb))
	c := h.head()

	require.NoError(t, h.s.EraseTenant(ctx, sa.Tenant))
	_, err := h.s.Get(ctx, ra.Tenant(), ra.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.FamilyState(ctx, ra.Tenant(), ra.Family())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.GetAPIKey(ctx, sa.Tenant, ka.KeyHash)
	require.ErrorIs(t, err, store.ErrNotFound)
	keys, err := h.s.ListAPIKeys(ctx, sa)
	require.NoError(t, err)
	require.Empty(t, keys)

	revs, _ := h.feed(c)
	require.Equal(t, []uuid.UUID{ra.Family()}, families(revs), "erased families reach the caches of other instances through the feed")
	require.Equal(t, sa.Tenant, revs[0].Tenant)

	got, err := h.s.Get(ctx, rb.Tenant(), rb.TokenHash())
	require.NoError(t, err)
	h.requireRecord(rb, got)
	_, err = h.s.GetAPIKey(ctx, sb.Tenant, kb.KeyHash)
	require.NoError(t, err)

	require.NoError(t, h.s.EraseTenant(ctx, sa.Tenant))
	revs, _ = h.feed(c)
	require.Len(t, revs, 1, "erasing an erased tenant appends nothing")
}

func fullRoundTrip(t *testing.T, h *harness) {
	ctx := context.Background()
	full := principaltest.Full()
	sealed, err := core.Seal(full)
	require.NoError(t, err)
	base := spec{
		subject: full.Subject(),
		lineage: full.Lineage(),
		sealed:  sealed,
		claims:  []byte(`{"roles":["admin","billing"]}`),
		epoch:   full.Epoch(),
		fp:      []byte("fingerprint-of-client-a"),
	}
	r := h.create(base)
	got, err := h.s.Get(ctx, r.Tenant(), r.TokenHash())
	require.NoError(t, err)
	h.requireRecord(r, got)
	require.True(t, reflect.DeepEqual(sealed, got.Sealed()), "the sealed attributes must come back byte for byte")

	base.family, base.hash, base.fp, base.ends = r.Family(), nil, []byte("fingerprint-of-client-b"), r.FamilyExpiresAt()
	next := h.build(base)
	_, err = h.rotate(r, next)
	require.NoError(t, err)
	got, err = h.s.Get(ctx, next.Tenant(), next.TokenHash())
	require.NoError(t, err)
	h.requireRecord(next, got)
	require.True(t, reflect.DeepEqual(sealed, got.Sealed()))
}

func createRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	require.ErrorIs(t, h.s.Create(ctx, tokens.RefreshRecord{}), tokens.ErrInvalidRecord)

	s := subject(t, "t")
	r := h.create(spec{subject: s})
	require.ErrorIs(t, h.s.Create(ctx, r), store.ErrConflict, "a duplicate token")
	same := h.build(spec{subject: s, lineage: r.Lineage(), family: r.Family()})
	require.ErrorIs(t, h.s.Create(ctx, same), store.ErrConflict, "a family is started once; later tokens come from rotation")
	_, err := h.s.Get(ctx, same.Tenant(), same.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func getStates(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	r := h.create(spec{subject: s})
	_, err := h.s.Get(ctx, tenant(t, "other"), r.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound, "a token is invisible from another tenant")
	_, err = h.s.Get(ctx, s.Tenant, digest())
	require.ErrorIs(t, err, store.ErrNotFound)

	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour, life: 24 * time.Hour})
	_, err = h.s.Get(ctx, s.Tenant, idle.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound, "an idle-expired token is not found")

	ended := h.create(spec{subject: s, created: now().Add(-3 * time.Hour), idle: time.Hour, life: 2 * time.Hour})
	_, err = h.s.Get(ctx, s.Tenant, ended.TokenHash())
	require.ErrorIs(t, err, tokens.ErrRevoked, "a token of an ended family reports the family")

	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, r.Family()))
	_, err = h.s.Get(ctx, s.Tenant, r.TokenHash())
	require.ErrorIs(t, err, tokens.ErrRevoked)
}

func rotate(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s, fp: []byte("fp-a"), claims: []byte("claims")})
	b := h.next(a, []byte("fp-a"))
	before := now()
	rot, err := h.rotate(a, b)
	require.NoError(t, err)
	require.Equal(t, a.Family(), rot.Family)
	require.False(t, rot.ConsumedAt.IsZero(), "the consumption instant is the store's")
	require.WithinDuration(t, before, rot.ConsumedAt, time.Minute)

	got, err := h.s.Get(ctx, s.Tenant, a.TokenHash())
	require.NoError(t, err, "a consumed token is still returned")
	h.requireRecord(a, got)
	got, err = h.s.Get(ctx, s.Tenant, b.TokenHash())
	require.NoError(t, err)
	h.requireRecord(b, got)
	require.True(t, h.state(a).Live(now()))

	c := h.next(b, []byte("fp-a"))
	_, err = h.rotate(b, c)
	require.NoError(t, err)
	_, err = h.s.Get(ctx, s.Tenant, c.TokenHash())
	require.NoError(t, err)
}

func rotateRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s, fp: []byte("fp")})

	_, err := h.s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash()})
	require.ErrorIs(t, err, tokens.ErrInvalidRecord)
	_, err = h.s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: a.TokenHash()[:16], Next: h.next(a, nil)})
	require.ErrorIs(t, err, tokens.ErrInvalidRecord)

	_, err = h.s.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: digest(), Next: h.next(a, nil)})
	require.ErrorIs(t, err, store.ErrNotFound)

	elsewhere := h.build(spec{subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}, lineage: a.Lineage(), family: a.Family()})
	_, err = h.rotate(a, elsewhere)
	require.ErrorIs(t, err, store.ErrNotFound, "a token is invisible from another tenant")

	for name, bad := range map[string]tokens.RefreshRecord{
		"subject": h.build(spec{subject: subject(t, "t"), lineage: a.Lineage(), family: a.Family()}),
		"lineage": h.build(spec{subject: s, family: a.Family()}),
		"family":  h.build(spec{subject: s, lineage: a.Lineage()}),
		"hash":    h.build(spec{subject: s, lineage: a.Lineage(), family: a.Family(), hash: a.TokenHash()}),
		"extended": h.build(spec{subject: s, lineage: a.Lineage(), family: a.Family(),
			ends: a.FamilyExpiresAt().Add(time.Hour)}),
	} {
		_, err := h.rotate(a, bad)
		require.ErrorIs(t, err, store.ErrConflict, name)
		_, err = h.s.Get(ctx, s.Tenant, bad.TokenHash())
		if name != "hash" {
			require.ErrorIs(t, err, store.ErrNotFound, name)
		}
	}
	_, err = h.rotate(a, h.next(a, []byte("fp")))
	require.NoError(t, err, "a refused rotation consumes nothing")

	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	_, err = h.rotate(idle, h.next(idle, nil))
	require.ErrorIs(t, err, store.ErrNotFound, "an idle-expired token cannot be rotated")

	revoked := h.create(spec{subject: s})
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, revoked.Family()))
	_, err = h.rotate(revoked, h.next(revoked, nil))
	require.ErrorIs(t, err, tokens.ErrRevoked)
}

func reuseWithinGrace(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	fp := []byte("client-fingerprint")
	a := h.create(spec{subject: s, fp: fp})
	b := h.next(a, fp)
	_, err := h.rotate(a, b)
	require.NoError(t, err)
	c0 := h.head()

	racer := h.next(a, fp)
	_, err = h.rotate(a, racer)
	require.ErrorIs(t, err, tokens.ErrConcurrent, "the same client racing its own rotation is benign")
	_, err = h.s.Get(ctx, s.Tenant, racer.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound, "a benign race issues nothing")
	require.True(t, h.state(a).Live(now()))
	revs, _ := h.feed(c0)
	require.Empty(t, revs)
	_, err = h.s.Get(ctx, s.Tenant, b.TokenHash())
	require.NoError(t, err)
}

func reuseFromOtherClient(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s, fp: []byte("victim")})
	b := h.next(a, []byte("victim"))
	_, err := h.rotate(a, b)
	require.NoError(t, err)
	c0 := h.head()

	thief := h.next(a, []byte("thief"))
	_, err = h.rotate(a, thief)
	require.ErrorIs(t, err, tokens.ErrReused)
	require.True(t, h.state(a).Revoked, "reuse from another client revokes the family")
	_, err = h.s.Get(ctx, s.Tenant, b.TokenHash())
	require.ErrorIs(t, err, tokens.ErrRevoked)
	_, err = h.s.Get(ctx, s.Tenant, thief.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{a.Family()}, families(revs))

	_, err = h.rotate(b, h.next(b, []byte("victim")))
	require.ErrorIs(t, err, tokens.ErrRevoked)
	_, err = h.rotate(a, h.next(a, []byte("thief")))
	require.ErrorIs(t, err, tokens.ErrRevoked)
	revs, _ = h.feed(c0)
	require.Len(t, revs, 1, "a revoked family is appended once")
}

func reuseWithoutFingerprint(t *testing.T, h *harness) {
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	_, err := h.rotate(a, h.next(a, nil))
	require.NoError(t, err)
	_, err = h.rotate(a, h.next(a, nil))
	require.ErrorIs(t, err, tokens.ErrReused, "without a fingerprint nothing proves the same client")
	require.True(t, h.state(a).Revoked)

	e := h.create(spec{subject: s})
	_, err = h.rotate(e, h.next(e, []byte{}))
	require.NoError(t, err)
	_, err = h.rotate(e, h.next(e, []byte{}))
	require.ErrorIs(t, err, tokens.ErrReused)
}

func reuseAfterGrace(t *testing.T, h *harness) {
	s := subject(t, "t")
	fp := []byte("same-client")
	a := h.create(spec{subject: s, fp: fp})
	_, err := h.rotate(a, h.next(a, fp))
	require.NoError(t, err)
	h.f.Travel(t, h.s, tokens.ReuseGrace+time.Second)
	_, err = h.rotate(a, h.next(a, fp))
	require.ErrorIs(t, err, tokens.ErrReused, "past the grace window in store time even the same client is a replay")
	require.True(t, h.state(a).Revoked)
}

func graceIgnoresIssuerClock(t *testing.T, h *harness) {
	s := subject(t, "t")
	fp := []byte("same-client")
	a := h.create(spec{subject: s, fp: fp})
	_, err := h.rotate(a, h.next(a, fp))
	require.NoError(t, err)
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		skewed := h.build(spec{subject: s, lineage: a.Lineage(), family: a.Family(), fp: fp, created: now().Add(skew),
			ends: a.FamilyExpiresAt()})
		_, err = h.rotate(a, skewed)
		require.ErrorIs(t, err, tokens.ErrConcurrent, "an issuer clock off by %s must not decide the grace window", skew)
	}
	require.False(t, h.state(a).Revoked)
}

func rotateConcurrent(t *testing.T, h *harness) {
	s := subject(t, "t")
	fp := []byte("tab")
	a := h.create(spec{subject: s, fp: fp})
	nexts := make([]tokens.RefreshRecord, goroutines)
	for i := range nexts {
		nexts[i] = h.next(a, fp)
	}
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() { _, errs[i] = h.rotate(a, nexts[i]) })
	}
	wg.Wait()
	ok, concurrent := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, tokens.ErrConcurrent):
			concurrent++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	require.Equal(t, 1, ok, "exactly one rotation consumes the token")
	require.Equal(t, goroutines-1, concurrent)
	require.False(t, h.state(a).Revoked)
}

func reissue(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	c0 := h.head()
	n := h.build(spec{subject: s, lineage: a.Lineage(), claims: []byte("new")})
	require.NoError(t, h.s.Reissue(ctx, tokens.ReissueRequest{Family: a.Family(), Next: n}))

	require.True(t, h.state(a).Revoked)
	require.True(t, h.state(n).Live(now()))
	got, err := h.s.Get(ctx, s.Tenant, n.TokenHash())
	require.NoError(t, err)
	h.requireRecord(n, got)
	_, err = h.s.Get(ctx, s.Tenant, a.TokenHash())
	require.ErrorIs(t, err, tokens.ErrRevoked)
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{a.Family()}, families(revs))

	again := h.build(spec{subject: s, lineage: a.Lineage()})
	require.ErrorIs(t, h.s.Reissue(ctx, tokens.ReissueRequest{Family: a.Family(), Next: again}), store.ErrConflict,
		"the old handle is gone")
	_, err = h.s.Get(ctx, s.Tenant, again.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func reissueRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	require.ErrorIs(t, h.s.Reissue(ctx, tokens.ReissueRequest{Family: a.Family()}), tokens.ErrInvalidRecord)
	for name, bad := range map[string]tokens.ReissueRequest{
		"unknown family": {Family: uuid.New(), Next: h.build(spec{subject: s, lineage: a.Lineage()})},
		"subject":        {Family: a.Family(), Next: h.build(spec{subject: subject(t, "t"), lineage: a.Lineage()})},
		"tenant":         {Family: a.Family(), Next: h.build(spec{subject: principal.Subject{Tenant: tenant(t, "other"), User: s.User}, lineage: a.Lineage()})},
		"lineage":        {Family: a.Family(), Next: h.build(spec{subject: s})},
		"same family":    {Family: a.Family(), Next: h.build(spec{subject: s, lineage: a.Lineage(), family: a.Family()})},
		"hash":           {Family: a.Family(), Next: h.build(spec{subject: s, lineage: a.Lineage(), hash: a.TokenHash()})},
	} {
		require.ErrorIs(t, h.s.Reissue(ctx, bad), store.ErrConflict, name)
		require.False(t, h.state(a).Revoked, "a refused reissue revokes nothing (%s)", name)
	}

	ended := h.create(spec{subject: s, created: now().Add(-3 * time.Hour), idle: time.Hour, life: 2 * time.Hour})
	require.ErrorIs(t, h.s.Reissue(ctx, tokens.ReissueRequest{Family: ended.Family(), Next: h.build(spec{subject: s, lineage: ended.Lineage()})}),
		store.ErrConflict, "an ended family cannot be reissued")
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, a.Family()))
	require.ErrorIs(t, h.s.Reissue(ctx, tokens.ReissueRequest{Family: a.Family(), Next: h.build(spec{subject: s, lineage: a.Lineage()})}),
		store.ErrConflict, "a revoked family cannot be reissued")
}

func reissueConcurrent(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	nexts := make([]tokens.RefreshRecord, goroutines)
	for i := range nexts {
		nexts[i] = h.build(spec{subject: s, lineage: a.Lineage()})
	}
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() { errs[i] = h.s.Reissue(ctx, tokens.ReissueRequest{Family: a.Family(), Next: nexts[i]}) })
	}
	wg.Wait()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, store.ErrConflict)
		_, gerr := h.s.Get(ctx, s.Tenant, nexts[i].TokenHash())
		require.ErrorIs(t, gerr, store.ErrNotFound)
	}
	require.Equal(t, 1, ok, "one reissue wins; the others find the old family gone")
}

func familyState(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	_, err := h.s.FamilyState(ctx, s.Tenant, uuid.New())
	require.ErrorIs(t, err, store.ErrNotFound)
	a := h.create(spec{subject: s})
	st := h.state(a)
	require.Equal(t, s, st.Subject)
	require.Equal(t, a.Lineage(), st.Lineage)
	require.False(t, st.Revoked)
	require.True(t, a.FamilyExpiresAt().Equal(st.ExpiresAt), "want %s, got %s", a.FamilyExpiresAt(), st.ExpiresAt)
	_, err = h.s.FamilyState(ctx, tenant(t, "other"), a.Family())
	require.ErrorIs(t, err, store.ErrNotFound, "a family is invisible from another tenant")

	_, err = h.rotate(a, h.next(a, nil))
	require.NoError(t, err)
	require.Equal(t, st, h.state(a), "rotation keeps the family state")
}

func revokeFamily(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	other := h.create(spec{subject: s})
	c0 := h.head()
	require.NoError(t, h.s.RevokeFamily(ctx, tenant(t, "other"), a.Family()))
	require.False(t, h.state(a).Revoked, "another tenant cannot revoke the family")
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, a.Family()))
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, a.Family()))
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, uuid.New()))
	require.True(t, h.state(a).Revoked)
	require.False(t, h.state(other).Revoked)
	revs, _ := h.feed(c0)
	require.Equal(t, []uuid.UUID{a.Family()}, families(revs), "revocation is idempotent")
	require.Equal(t, s.Tenant, revs[0].Tenant)
	require.False(t, revs[0].At.IsZero())
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
	require.True(t, h.state(l1).Revoked)
	require.False(t, h.state(l2).Revoked, "the kept lineage survives")
	require.True(t, h.state(l3).Revoked)
	require.False(t, h.state(neighbour).Revoked)
	require.False(t, h.state(twin).Revoked, "the same user id in another tenant is another subject")
	revs, c1 := h.feed(c0)
	require.ElementsMatch(t, []uuid.UUID{l1.Family(), l3.Family()}, families(revs))

	require.NoError(t, h.s.RevokeForSubject(ctx, s, keep))
	revs, _ = h.feed(c1)
	require.Empty(t, revs, "revocation is idempotent")
	require.NoError(t, h.s.RevokeForSubject(ctx, s, uuid.Nil))
	require.True(t, h.state(l2).Revoked, "uuid.Nil keeps nothing")
	revs, _ = h.feed(c1)
	require.Equal(t, []uuid.UUID{l2.Family()}, families(revs))
}

func revocationsBackdated(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	b := h.create(spec{subject: s})
	c := h.create(spec{subject: s})
	start := h.head()
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, a.Family()))
	first, c1 := h.feed(start)
	require.Len(t, first, 1)
	require.True(t, c1.After(start))

	h.f.Travel(t, h.s, -time.Hour)
	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, b.Family()))
	second, c2 := h.feed(c1)
	require.Equal(t, []uuid.UUID{b.Family()}, families(second), "a back-dated revocation is still returned after the cursor")
	both, _ := h.feed(start)
	require.Len(t, both, 2)
	require.True(t, both[1].At.Before(both[0].At), "the second revocation is stamped earlier than the first")
	require.True(t, c2.After(c1))

	none, c3 := h.feed(c2)
	require.Empty(t, none)
	require.Equal(t, c2, c3, "an empty read keeps the cursor")

	require.NoError(t, h.s.RevokeFamily(ctx, s.Tenant, c.Family()))
	all, _ := h.feed(start)
	require.Equal(t, []uuid.UUID{a.Family(), b.Family(), c.Family()}, families(all), "oldest first in feed order")
}

func deleteForSubject(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	a := h.create(spec{subject: s})
	k := apiKey(s)
	require.NoError(t, h.s.CreateAPIKey(ctx, k))
	other := h.create(spec{subject: subject(t, "t")})
	twin := principal.Subject{Tenant: tenant(t, "other"), User: s.User}
	tk := apiKey(twin)
	require.NoError(t, h.s.CreateAPIKey(ctx, tk))

	require.NoError(t, h.s.DeleteForSubject(ctx, s))
	_, err := h.s.Get(ctx, s.Tenant, a.TokenHash())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.FamilyState(ctx, s.Tenant, a.Family())
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.GetAPIKey(ctx, s.Tenant, k.KeyHash)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = h.s.Get(ctx, other.Tenant(), other.TokenHash())
	require.NoError(t, err)
	_, err = h.s.GetAPIKey(ctx, twin.Tenant, tk.KeyHash)
	require.NoError(t, err)
	require.NoError(t, h.s.DeleteForSubject(ctx, s))
}

func apiKey(owner principal.Subject) tokens.APIKey {
	created := now()
	return tokens.APIKey{
		ID:           uuid.New(),
		Owner:        owner,
		Kind:         "service",
		Name:         "ci deploy",
		KeyHash:      digest(),
		AppClaims:    []byte(`{"scopes":["deploy"]}`),
		CreatedEpoch: 42,
		CreatedAt:    created,
		ExpiresAt:    created.Add(30 * 24 * time.Hour),
	}
}

func apiKeys(t *testing.T, h *harness) {
	ctx := context.Background()
	owner := subject(t, "t")
	k1 := apiKey(owner)
	k1.CreatedAt = k1.CreatedAt.Add(-time.Minute)
	k2 := apiKey(owner)
	k2.AppClaims, k2.ExpiresAt, k2.Kind, k2.Name, k2.CreatedEpoch = nil, time.Time{}, "pat", "", 0
	stranger := apiKey(subject(t, "t"))
	for _, k := range []tokens.APIKey{k2, k1, stranger} {
		require.NoError(t, h.s.CreateAPIKey(ctx, k))
	}

	for _, want := range []tokens.APIKey{k1, k2} {
		got, err := h.s.GetAPIKey(ctx, owner.Tenant, want.KeyHash)
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(want, got), "api key differs after the round trip:\nwant %#v\ngot  %#v", want, got)
	}
	_, err := h.s.GetAPIKey(ctx, tenant(t, "other"), k1.KeyHash)
	require.ErrorIs(t, err, store.ErrNotFound, "a key is invisible from another tenant")
	_, err = h.s.GetAPIKey(ctx, owner.Tenant, digest())
	require.ErrorIs(t, err, store.ErrNotFound)

	list, err := h.s.ListAPIKeys(ctx, owner)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, []uuid.UUID{k1.ID, k2.ID}, []uuid.UUID{list[0].ID, list[1].ID}, "oldest first")

	require.ErrorIs(t, h.s.RevokeAPIKey(ctx, owner, stranger.ID), store.ErrNotFound, "an owner revokes only its own keys")
	require.ErrorIs(t, h.s.RevokeAPIKey(ctx, owner, uuid.New()), store.ErrNotFound)
	require.NoError(t, h.s.RevokeAPIKey(ctx, owner, k1.ID))
	revoked, err := h.s.GetAPIKey(ctx, owner.Tenant, k1.KeyHash)
	require.NoError(t, err, "a revoked key is still returned")
	require.False(t, revoked.RevokedAt.IsZero())
	require.NoError(t, h.s.RevokeAPIKey(ctx, owner, k1.ID))
	again, err := h.s.GetAPIKey(ctx, owner.Tenant, k1.KeyHash)
	require.NoError(t, err)
	require.True(t, revoked.RevokedAt.Equal(again.RevokedAt), "revocation is idempotent")
	list, err = h.s.ListAPIKeys(ctx, owner)
	require.NoError(t, err)
	require.Len(t, list, 2, "revoked keys are listed")
	s, err := h.s.GetAPIKey(ctx, stranger.Owner.Tenant, stranger.KeyHash)
	require.NoError(t, err)
	require.True(t, s.RevokedAt.IsZero())

	expired := apiKey(owner)
	expired.CreatedAt, expired.ExpiresAt = now().Add(-2*time.Hour), now().Add(-time.Hour)
	require.NoError(t, h.s.CreateAPIKey(ctx, expired))
	_, err = h.s.GetAPIKey(ctx, owner.Tenant, expired.KeyHash)
	require.ErrorIs(t, err, store.ErrNotFound, "an expired key is not found")
}

func apiKeyRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	owner := subject(t, "t")
	require.ErrorIs(t, h.s.CreateAPIKey(ctx, tokens.APIKey{}), tokens.ErrInvalidRecord)
	bad := apiKey(owner)
	bad.KeyHash = bad.KeyHash[:8]
	require.ErrorIs(t, h.s.CreateAPIKey(ctx, bad), tokens.ErrInvalidRecord)

	k := apiKey(owner)
	require.NoError(t, h.s.CreateAPIKey(ctx, k))
	dupID := apiKey(owner)
	dupID.ID = k.ID
	require.ErrorIs(t, h.s.CreateAPIKey(ctx, dupID), store.ErrConflict, "a duplicate id")
	dupHash := apiKey(owner)
	dupHash.KeyHash = k.KeyHash
	require.ErrorIs(t, h.s.CreateAPIKey(ctx, dupHash), store.ErrConflict, "a duplicate key hash")
	got, err := h.s.GetAPIKey(ctx, owner.Tenant, k.KeyHash)
	require.NoError(t, err)
	require.Equal(t, k.ID, got.ID, "a refused key overwrites nothing")
}

func apiKeyConcurrentID(t *testing.T, h *harness) {
	ctx := context.Background()
	owner := subject(t, "t")
	id := uuid.New()
	keys := make([]tokens.APIKey, goroutines)
	errs := make([]error, goroutines)
	for i := range keys {
		keys[i] = apiKey(owner)
		keys[i].ID = id
	}
	var wg sync.WaitGroup
	for i := range keys {
		wg.Go(func() { errs[i] = h.s.CreateAPIKey(ctx, keys[i]) })
	}
	wg.Wait()
	created := 0
	for _, err := range errs {
		if err == nil {
			created++
			continue
		}
		require.ErrorIs(t, err, store.ErrConflict)
	}
	require.Equal(t, 1, created, "concurrent creates of one id store exactly one key")
	list, err := h.s.ListAPIKeys(ctx, owner)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func reapExpired(t *testing.T, h *harness) {
	ctx := context.Background()
	s := subject(t, "t")
	live := h.create(spec{subject: s})
	idle := h.create(spec{subject: s, created: now().Add(-2 * time.Hour), idle: time.Hour})
	ended := h.create(spec{subject: s, created: now().Add(-3 * time.Hour), idle: time.Hour, life: 2 * time.Hour})
	key := apiKey(s)
	forever := apiKey(s)
	forever.ExpiresAt = time.Time{}
	gone := apiKey(s)
	gone.CreatedAt, gone.ExpiresAt = now().Add(-2*time.Hour), now().Add(-time.Hour)
	for _, k := range []tokens.APIKey{key, forever, gone} {
		require.NoError(t, h.s.CreateAPIKey(ctx, k))
	}

	n, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(3))
	_, err = h.s.Get(ctx, s.Tenant, live.TokenHash())
	require.NoError(t, err)
	for _, r := range []tokens.RefreshRecord{idle, ended} {
		_, err = h.s.FamilyState(ctx, s.Tenant, r.Family())
		require.ErrorIs(t, err, store.ErrNotFound, "reaped families are gone")
	}
	for _, k := range []tokens.APIKey{key, forever} {
		_, err = h.s.GetAPIKey(ctx, s.Tenant, k.KeyHash)
		require.NoError(t, err)
	}
	list, err := h.s.ListAPIKeys(ctx, s)
	require.NoError(t, err)
	require.Len(t, list, 2, "the expired key is reaped")

	n, err = h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}
