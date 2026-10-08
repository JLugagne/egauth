// Package storetest holds the conformance suite of keys.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

const goroutines = 32

// Fixtures is what the store implementation's test hands the suite through Seed.
type Fixtures struct {
	// SeedV016 inserts k, whose AADVersion is AADVersionLegacy, the way a v0.16 deployment left it.
	// Stores refuse such a write through CreateTenant, PutKey and Rotate.
	SeedV016 func(t *testing.T, s keys.Store, k keys.Key)
	// AgeFeed moves every change feed entry of s d into the past, so that ReapExpired prunes the
	// entries it pushes beyond the feed retention.
	AgeFeed func(t *testing.T, s keys.Store, d time.Duration)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the keys.Store contract against stores returned by newStore. Each subtest gets a
// fresh, empty store, which reads the wall clock. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) keys.Store) {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, Fixtures{...}) before Run")
	}
	f := v.(Fixtures)
	if f.SeedV016 == nil || f.AgeFeed == nil {
		t.Fatal("storetest: every Fixtures field is required")
	}
	suites := map[string]func(*testing.T, *harness){
		"Base":                 baseSuite,
		"CreateTenant":         createTenant,
		"CreateTenantRace":     createTenantRace,
		"PutKey":               putKey,
		"KeyRoundTrip":         keyRoundTrip,
		"ActiveKey":            activeKey,
		"ExpirySemantics":      expirySemantics,
		"VerificationKeys":     verificationKeys,
		"Rotate":               rotate,
		"RotateRefusals":       rotateRefusals,
		"RotateNotSigner":      rotateNotSigner,
		"RotateOutranked":      rotateOutranked,
		"RotateRace":           rotateRace,
		"RevokeTenantKeys":     revokeTenantKeys,
		"TombstoneBlocks":      tombstoneBlocks,
		"TombstoneRace":        tombstoneRace,
		"EraseTenant":          eraseTenant,
		"ReapExpired":          reapExpired,
		"ChangesSince":         changesSince,
		"ChangesEveryMutation": changesEveryMutation,
		"ChangesConcurrent":    changesConcurrent,
		"ChangesPrunedGap":     changesPrunedGap,
		"ReapRetiredForever":   reapRetiredForever,
		"SealedOpaque":         sealedOpaque,
		"LegacyUpgrade":        legacyUpgrade,
		"ReplaceSealedCAS":     replaceSealedCAS,
		"ReplaceSealedRace":    replaceSealedRace,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, &harness{s: newStore(t), f: f}) })
	}
}

type harness struct {
	s keys.Store
	f Fixtures
}

func tenant(t *testing.T, name string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func now() time.Time { return clock.Clock{}.Now().UTC().Truncate(time.Microsecond) }

func key(t *testing.T, tn, id string) keys.Key {
	t.Helper()
	return keys.Key{
		Tenant:     tenant(t, tn),
		KeyID:      id,
		Alg:        "EdDSA",
		Sealed:     []byte("sealed-" + tn + "-" + id),
		AADVersion: keys.AADVersionCurrent,
		CreatedAt:  now().Add(-time.Minute),
	}
}

func at(d time.Duration) time.Time { return now().Add(d) }

func (h *harness) create(t *testing.T, k keys.Key) {
	t.Helper()
	require.NoError(t, h.s.CreateTenant(context.Background(), k))
}

func (h *harness) put(t *testing.T, k keys.Key) {
	t.Helper()
	require.NoError(t, h.s.PutKey(context.Background(), k))
}

func (h *harness) changes(t *testing.T, c store.Cursor) ([]keys.Change, store.Cursor) {
	t.Helper()
	out, next, err := h.s.ChangesSince(context.Background(), c)
	require.NoError(t, err)
	return out, next
}

func (h *harness) verifying(t *testing.T, tn principal.TenantID) []string {
	t.Helper()
	list, err := h.s.VerificationKeys(context.Background(), tn)
	require.NoError(t, err)
	var ids []string
	for _, k := range list {
		ids = append(ids, k.KeyID)
	}
	return ids
}

func baseSuite(t *testing.T, h *harness) {
	ctx := context.Background()
	require.NoError(t, h.s.Ping(ctx))
	require.True(t, h.s.Durability().Valid())
	n, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	n2, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n2)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, h.s.CreateTenant(cancelled, key(t, "tenant-a", "k1")))
}

func createTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	ok, err := h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.False(t, ok)
	_, err = h.s.ActiveKey(ctx, a)
	require.ErrorIs(t, err, keys.ErrNoActiveKey)

	first := key(t, "tenant-a", "k1")
	h.create(t, first)
	ok, err = h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.True(t, ok)
	require.ErrorIs(t, h.s.CreateTenant(ctx, key(t, "tenant-a", "k2")), store.ErrConflict, "a tenant is provisioned once")
	other, err := h.s.TenantExists(ctx, tenant(t, "tenant-b"))
	require.NoError(t, err)
	require.False(t, other)

	legacy := key(t, "tenant-b", "k1")
	legacy.AADVersion = keys.AADVersionLegacy
	require.ErrorIs(t, h.s.CreateTenant(ctx, legacy), keys.ErrLegacyAADVersion, "v0.16 material is never written fresh (C-58)")
	for name, mutate := range map[string]func(*keys.Key){
		"no id":     func(k *keys.Key) { k.KeyID = "" },
		"no alg":    func(k *keys.Key) { k.Alg = "" },
		"no sealed": func(k *keys.Key) { k.Sealed = nil },
	} {
		k := key(t, "tenant-b", "k1")
		mutate(&k)
		err := h.s.CreateTenant(ctx, k)
		require.Error(t, err, name)
		require.NotErrorIs(t, err, keys.ErrLegacyAADVersion, name)
	}
	other, err = h.s.TenantExists(ctx, tenant(t, "tenant-b"))
	require.NoError(t, err)
	require.False(t, other, "a refused provisioning stores nothing")

	single := key(t, "tenant-a", "single")
	single.Tenant = principal.TenantID{}
	h.create(t, single)
	got, err := h.s.ActiveKey(ctx, principal.TenantID{})
	require.NoError(t, err)
	require.Equal(t, "single", got.KeyID, "the single tenant is a tenant")
}

func createTenantRace(t *testing.T, h *harness) {
	candidates := make([]keys.Key, goroutines)
	for i := range candidates {
		candidates[i] = key(t, "tenant-a", fmt.Sprintf("k%d", i))
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			err := h.s.CreateTenant(context.Background(), candidates[i])
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrConflict):
				conflicts.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "exactly one concurrent provisioning wins")
	require.EqualValues(t, goroutines-1, conflicts.Load())
	list := h.verifying(t, tenant(t, "tenant-a"))
	require.Len(t, list, 1)
}

func putKey(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.put(t, key(t, "tenant-a", "k1"))
	require.ErrorIs(t, h.s.PutKey(ctx, key(t, "tenant-a", "k1")), store.ErrConflict, "a key id is never reused")
	reused := key(t, "tenant-a", "k1")
	reused.Sealed = []byte("other material")
	require.ErrorIs(t, h.s.PutKey(ctx, reused), store.ErrConflict)
	h.put(t, key(t, "tenant-b", "k1"))
	h.put(t, key(t, "tenant-a", "k2"))
	require.ElementsMatch(t, []string{"k1", "k2"}, h.verifying(t, a))

	legacy := key(t, "tenant-a", "k3")
	legacy.AADVersion = keys.AADVersionLegacy
	require.ErrorIs(t, h.s.PutKey(ctx, legacy), keys.ErrLegacyAADVersion)
	bad := key(t, "tenant-a", "k4")
	bad.Alg = ""
	require.Error(t, h.s.PutKey(ctx, bad))
	require.ElementsMatch(t, []string{"k1", "k2"}, h.verifying(t, a))
}

func keyRoundTrip(t *testing.T, h *harness) {
	ctx := context.Background()
	k := key(t, "tenant-a", "k1")
	k.Alg = "RS256"
	k.NotAfter = at(time.Hour)
	h.put(t, k)
	got, err := h.s.ActiveKey(ctx, k.Tenant)
	require.NoError(t, err)
	require.Equal(t, k, got, "every field of the key round-trips in UTC")
	got.Sealed[0] ^= 0xff
	again, err := h.s.ActiveKey(ctx, k.Tenant)
	require.NoError(t, err)
	require.Equal(t, k.Sealed, again.Sealed, "the store keeps its own copy of the material")

	retired := key(t, "tenant-a", "old")
	retiredAt := at(-time.Hour)
	retired.RetiredAt = &retiredAt
	retired.NotAfter = at(time.Hour)
	h.put(t, retired)
	list, err := h.s.VerificationKeys(ctx, k.Tenant)
	require.NoError(t, err)
	var found *keys.Key
	for i := range list {
		if list[i].KeyID == "old" {
			found = &list[i]
		}
	}
	require.NotNil(t, found)
	require.NotNil(t, found.RetiredAt)
	require.True(t, retiredAt.Equal(*found.RetiredAt))
}

func activeKey(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	oldest := key(t, "tenant-a", "oldest")
	oldest.CreatedAt = at(-3 * time.Hour)
	newer := key(t, "tenant-a", "newer")
	newer.CreatedAt = at(-time.Hour)
	expired := key(t, "tenant-a", "expired")
	expired.CreatedAt = at(-30 * time.Minute)
	expired.NotAfter = at(-time.Minute)
	retired := key(t, "tenant-a", "retired")
	retired.CreatedAt = at(-20 * time.Minute)
	retiredAt := at(-10 * time.Minute)
	retired.RetiredAt = &retiredAt
	retired.NotAfter = at(time.Hour)
	for _, k := range []keys.Key{oldest, newer, expired, retired} {
		h.put(t, k)
	}
	got, err := h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "newer", got.KeyID, "the newest key that is neither retired nor expired signs")
	require.True(t, got.IsActive(now()))

	_, err = h.s.ActiveKey(ctx, tenant(t, "tenant-b"))
	require.ErrorIs(t, err, keys.ErrNoActiveKey)

	h.put(t, key(t, "tenant-c", "only-retired"))
	retiredOnly := key(t, "tenant-d", "r")
	ra := at(-time.Minute)
	retiredOnly.RetiredAt = &ra
	h.put(t, retiredOnly)
	_, err = h.s.ActiveKey(ctx, tenant(t, "tenant-d"))
	require.ErrorIs(t, err, keys.ErrNoActiveKey, "a tenant with keys but no active signer")
}

func expirySemantics(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	n := now()

	lifetime, err := keys.ExpireAfter(time.Hour)
	require.NoError(t, err)
	notAfter, err := lifetime.At(n, 0)
	require.NoError(t, err)
	timed := key(t, "tenant-a", "timed")
	timed.NotAfter = notAfter
	forever := key(t, "tenant-a", "forever")
	forever.NotAfter, err = keys.NeverExpire().At(n, 0)
	require.NoError(t, err)
	require.True(t, forever.NotAfter.IsZero(), "NeverExpire stores as no NotAfter")
	byDefault := key(t, "tenant-a", "default")
	byDefault.NotAfter, err = keys.DefaultExpiry().At(n, 2*time.Hour)
	require.NoError(t, err)
	for _, k := range []keys.Key{timed, forever, byDefault} {
		h.put(t, k)
	}
	require.ElementsMatch(t, []string{"timed", "forever", "default"}, h.verifying(t, a))

	lapsed := key(t, "tenant-a", "lapsed")
	lapsed.NotAfter = at(-time.Second)
	h.put(t, lapsed)
	require.NotContains(t, h.verifying(t, a), "lapsed", "a key past NotAfter never verifies")

	noEnd := key(t, "tenant-b", "retired-no-end")
	ra := at(-time.Minute)
	noEnd.RetiredAt = &ra
	h.put(t, noEnd)
	require.Empty(t, h.verifying(t, tenant(t, "tenant-b")), "a retired key without NotAfter never verifies (X-16)")

	_, err = keys.NeverExpire().OverlapUntil(n, time.Hour)
	require.ErrorIs(t, err, keys.ErrUnboundedOverlap)
	forever2 := key(t, "tenant-c", "k1")
	h.put(t, forever2)
	require.ErrorIs(t, h.s.Rotate(ctx, keys.Rotation{
		Previous: "k1", Next: key(t, "tenant-c", "k2"), RetiredAt: n,
	}), keys.ErrInvalidRotation, "an overlap with no end is refused by the store too")
	require.Equal(t, []string{"k1"}, h.verifying(t, tenant(t, "tenant-c")))
}

func verificationKeys(t *testing.T, h *harness) {
	ctx := context.Background()
	empty, err := h.s.VerificationKeys(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, empty)
	h.put(t, key(t, "tenant-a", "k1"))
	h.put(t, key(t, "tenant-b", "k2"))
	require.Equal(t, []string{"k1"}, h.verifying(t, tenant(t, "tenant-a")), "keys of the tenant only")
}

func rotation(t *testing.T, tn, prev, next string) keys.Rotation {
	t.Helper()
	return keys.Rotation{
		Previous:     prev,
		Next:         key(t, tn, next),
		RetiredAt:    now(),
		OverlapUntil: at(time.Hour),
	}
}

func rotate(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.create(t, key(t, "tenant-a", "k1"))
	r := rotation(t, "tenant-a", "k1", "k2")
	r.Next.CreatedAt = now()
	require.NoError(t, h.s.Rotate(ctx, r))

	active, err := h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "k2", active.KeyID)
	require.ElementsMatch(t, []string{"k1", "k2"}, h.verifying(t, a), "the retired key verifies during the overlap")
	list, err := h.s.VerificationKeys(ctx, a)
	require.NoError(t, err)
	for _, k := range list {
		if k.KeyID == "k1" {
			require.NotNil(t, k.RetiredAt)
			require.True(t, r.RetiredAt.Equal(*k.RetiredAt))
			require.True(t, r.OverlapUntil.Equal(k.NotAfter), "NotAfter becomes the end of the overlap")
		}
	}

	earlier := rotation(t, "tenant-a", "k2", "k3")
	earlier.Next.CreatedAt = now()
	require.NoError(t, h.s.Rotate(ctx, earlier))
	next := rotation(t, "tenant-a", "k3", "k4")
	next.Next.CreatedAt = now()
	next.OverlapUntil = at(48 * time.Hour)
	require.NoError(t, h.s.Rotate(ctx, next))

	short := key(t, "tenant-b", "s1")
	short.NotAfter = at(10 * time.Minute)
	h.create(t, short)
	long := rotation(t, "tenant-b", "s1", "s2")
	long.OverlapUntil = at(5 * time.Hour)
	require.NoError(t, h.s.Rotate(ctx, long))
	list, err = h.s.VerificationKeys(ctx, tenant(t, "tenant-b"))
	require.NoError(t, err)
	for _, k := range list {
		if k.KeyID == "s1" {
			require.True(t, short.NotAfter.Equal(k.NotAfter), "a key that expires sooner keeps its own NotAfter")
		}
	}
}

func rotateRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.create(t, key(t, "tenant-a", "k1"))

	legacy := rotation(t, "tenant-a", "k1", "k2")
	legacy.Next.AADVersion = keys.AADVersionLegacy
	require.ErrorIs(t, h.s.Rotate(ctx, legacy), keys.ErrInvalidRotation)
	same := rotation(t, "tenant-a", "k1", "k1")
	require.ErrorIs(t, h.s.Rotate(ctx, same), keys.ErrInvalidRotation)
	noPrev := rotation(t, "tenant-a", "", "k2")
	require.ErrorIs(t, h.s.Rotate(ctx, noPrev), keys.ErrInvalidRotation)
	noOverlap := rotation(t, "tenant-a", "k1", "k2")
	noOverlap.OverlapUntil = time.Time{}
	require.ErrorIs(t, h.s.Rotate(ctx, noOverlap), keys.ErrInvalidRotation)
	noAlg := rotation(t, "tenant-a", "k1", "k2")
	noAlg.Next.Alg = ""
	require.ErrorIs(t, h.s.Rotate(ctx, noAlg), keys.ErrInvalidRotation)
	noMaterial := rotation(t, "tenant-a", "k1", "k2")
	noMaterial.Next.Sealed = nil
	require.ErrorIs(t, h.s.Rotate(ctx, noMaterial), keys.ErrInvalidRotation)
	require.Equal(t, []string{"k1"}, h.verifying(t, a), "a refused rotation retires nothing")

	unknown := rotation(t, "tenant-a", "ghost", "k2")
	require.ErrorIs(t, h.s.Rotate(ctx, unknown), store.ErrConflict, "Previous must be the tenant's signer")
	elsewhere := rotation(t, "tenant-b", "k1", "k2")
	require.ErrorIs(t, h.s.Rotate(ctx, elsewhere), store.ErrConflict, "Previous is scoped to the tenant")

	taken := key(t, "tenant-a", "taken")
	taken.CreatedAt = at(-time.Hour)
	h.put(t, taken)
	reuse := rotation(t, "tenant-a", "k1", "taken")
	require.ErrorIs(t, h.s.Rotate(ctx, reuse), store.ErrConflict, "the new key id exists in the tenant")

	good := rotation(t, "tenant-a", "k1", "k2")
	good.Next.CreatedAt = now()
	require.NoError(t, h.s.Rotate(ctx, good))
	stale := rotation(t, "tenant-a", "k1", "k3")
	require.ErrorIs(t, h.s.Rotate(ctx, stale), store.ErrConflict, "a retired key cannot be rotated again")
	require.NotContains(t, h.verifying(t, a), "k3", "on any error nothing changes")
}

func rotateNotSigner(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	older := key(t, "tenant-a", "k1")
	older.CreatedAt = at(-2 * time.Minute)
	h.create(t, older)
	h.put(t, key(t, "tenant-a", "k2"))
	active, err := h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "k2", active.KeyID)

	stale := rotation(t, "tenant-a", "k1", "k3")
	require.ErrorIs(t, h.s.Rotate(ctx, stale), store.ErrConflict, "an unretired key that is not the signer cannot be rotated")
	active, err = h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "k2", active.KeyID)
	require.ElementsMatch(t, []string{"k1", "k2"}, h.verifying(t, a), "on any error nothing changes")
	list, err := h.s.VerificationKeys(ctx, a)
	require.NoError(t, err)
	for _, k := range list {
		require.Nil(t, k.RetiredAt, "the refused rotation retired %s", k.KeyID)
	}

	expired := key(t, "tenant-b", "e1")
	expired.NotAfter = at(-time.Second)
	h.create(t, expired)
	lapsed := rotation(t, "tenant-b", "e1", "e2")
	require.ErrorIs(t, h.s.Rotate(ctx, lapsed), store.ErrConflict, "an expired key is no longer the signer")
}

func rotateOutranked(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	older := key(t, "tenant-a", "k1")
	older.CreatedAt = at(-3 * time.Minute)
	h.create(t, older)
	h.put(t, key(t, "tenant-a", "k2"))
	backdated := rotation(t, "tenant-a", "k2", "k3")
	backdated.Next.CreatedAt = at(-4 * time.Minute)
	require.ErrorIs(t, h.s.Rotate(ctx, backdated), store.ErrConflict, "a Next that would not become the signer is refused")
	active, err := h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "k2", active.KeyID, "on any error nothing changes")
	require.ElementsMatch(t, []string{"k1", "k2"}, h.verifying(t, a))

	good := rotation(t, "tenant-a", "k2", "k3")
	good.Next.CreatedAt = now()
	require.NoError(t, h.s.Rotate(ctx, good))
	active, err = h.s.ActiveKey(ctx, a)
	require.NoError(t, err)
	require.Equal(t, "k3", active.KeyID, "Rotation makes Next the active signer")
}

func rotateRace(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.create(t, key(t, "tenant-a", "k1"))
	rotations := make([]keys.Rotation, goroutines)
	for i := range rotations {
		rotations[i] = rotation(t, "tenant-a", "k1", fmt.Sprintf("next-%d", i))
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			err := h.s.Rotate(ctx, rotations[i])
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrConflict):
				conflicts.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "exactly one concurrent rotation wins")
	require.EqualValues(t, goroutines-1, conflicts.Load())
	require.Len(t, h.verifying(t, a), 2, "the winner's key and the retired one")
}

func revokeTenantKeys(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.create(t, key(t, "tenant-a", "k1"))
	h.put(t, key(t, "tenant-a", "k2"))
	h.create(t, key(t, "tenant-b", "k1"))
	require.NoError(t, h.s.RevokeTenantKeys(ctx, a))
	ok, err := h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, h.verifying(t, a))
	require.Len(t, h.verifying(t, tenant(t, "tenant-b")), 1)
	require.NoError(t, h.s.RevokeTenantKeys(ctx, a), "revoking twice is idempotent")
	dead, err := h.s.IsTombstoned(ctx, a)
	require.NoError(t, err)
	require.False(t, dead, "revoking is not erasing")
	h.create(t, key(t, "tenant-a", "again"))
}

func tombstoneBlocks(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	dead, err := h.s.IsTombstoned(ctx, a)
	require.NoError(t, err)
	require.False(t, dead)
	h.create(t, key(t, "tenant-a", "k1"))
	h.create(t, key(t, "tenant-b", "k1"))
	require.NoError(t, h.s.Tombstone(ctx, a))
	dead, err = h.s.IsTombstoned(ctx, a)
	require.NoError(t, err)
	require.True(t, dead)
	other, err := h.s.IsTombstoned(ctx, tenant(t, "tenant-b"))
	require.NoError(t, err)
	require.False(t, other)
	require.Empty(t, h.verifying(t, a), "a tombstone erases the tenant's keys")
	require.Len(t, h.verifying(t, tenant(t, "tenant-b")), 1)

	require.ErrorIs(t, h.s.CreateTenant(ctx, key(t, "tenant-a", "k2")), keys.ErrTenantTombstoned, "T-13")
	require.ErrorIs(t, h.s.PutKey(ctx, key(t, "tenant-a", "k3")), keys.ErrTenantTombstoned, "T-13")
	h.create(t, key(t, "tenant-c", "k1"))
	require.NoError(t, h.s.Tombstone(ctx, a), "tombstoning twice is idempotent")
	ok, err := h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.False(t, ok)

	rot := rotation(t, "tenant-c", "k1", "k2")
	require.NoError(t, h.s.Tombstone(ctx, tenant(t, "tenant-c")))
	require.ErrorIs(t, h.s.Rotate(ctx, rot), keys.ErrTenantTombstoned, "a rotation cannot resurrect an erased tenant")
	ok, err = h.s.TenantExists(ctx, tenant(t, "tenant-c"))
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, h.s.Tombstone(ctx, tenant(t, "never-had-keys")))
	dead, err = h.s.IsTombstoned(ctx, tenant(t, "never-had-keys"))
	require.NoError(t, err)
	require.True(t, dead, "an unprovisioned tenant can be tombstoned in advance")
}

func tombstoneRace(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	candidates := make([]keys.Key, goroutines)
	for i := range candidates {
		candidates[i] = key(t, "tenant-a", fmt.Sprintf("k%d", i))
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			if i%4 == 0 {
				_ = h.s.Tombstone(ctx, a)
				return
			}
			_ = h.s.PutKey(ctx, candidates[i])
		})
	}
	close(start)
	wg.Wait()
	require.NoError(t, h.s.Tombstone(ctx, a))
	ok, err := h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.False(t, ok, "no provisioning survives the tombstone")
	dead, err := h.s.IsTombstoned(ctx, a)
	require.NoError(t, err)
	require.True(t, dead)
}

func eraseTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	h.create(t, key(t, "tenant-a", "k1"))
	h.create(t, key(t, "tenant-b", "k1"))
	legacy := key(t, "tenant-a", "v0")
	h.f.SeedV016(t, h.s, legacyOf(legacy, []byte("v016")))

	require.NoError(t, h.s.EraseTenant(ctx, a))
	ok, err := h.s.TenantExists(ctx, a)
	require.NoError(t, err)
	require.False(t, ok)
	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "legacy keys of the tenant are erased too")
	require.Len(t, h.verifying(t, tenant(t, "tenant-b")), 1, "another tenant is untouched")
	dead, err := h.s.IsTombstoned(ctx, a)
	require.NoError(t, err)
	require.True(t, dead, "EraseTenant leaves a tombstone (T-13)")
	require.ErrorIs(t, h.s.CreateTenant(ctx, key(t, "tenant-a", "k2")), keys.ErrTenantTombstoned)
	require.NoError(t, h.s.EraseTenant(ctx, a), "erasing twice is idempotent")
}

func reapExpired(t *testing.T, h *harness) {
	ctx := context.Background()
	live := key(t, "tenant-a", "live")
	gone1 := key(t, "tenant-a", "gone1")
	gone1.NotAfter = at(-time.Hour)
	gone2 := key(t, "tenant-b", "gone2")
	gone2.NotAfter = at(-time.Minute)
	retired := key(t, "tenant-b", "retired-live")
	ra := at(-time.Hour)
	retired.RetiredAt = &ra
	retired.NotAfter = at(time.Hour)
	for _, k := range []keys.Key{live, gone1, gone2, retired} {
		h.put(t, k)
	}
	_, cur := h.changes(t, store.Cursor{})
	n, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, n, "keys past NotAfter in every tenant are removed")
	require.Equal(t, []string{"live"}, h.verifying(t, tenant(t, "tenant-a")))
	require.Equal(t, []string{"retired-live"}, h.verifying(t, tenant(t, "tenant-b")))
	list, _ := h.changes(t, cur)
	var tenants []string
	for _, c := range list {
		tenants = append(tenants, c.Tenant.String())
	}
	require.ElementsMatch(t, []string{"tenant-a", "tenant-b"}, tenants, "the keys a reap removes are in the feed (T-15)")
	n, err = h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}

func changesSince(t *testing.T, h *harness) {
	empty, c0 := h.changes(t, store.Cursor{})
	require.Empty(t, empty)
	require.True(t, c0.IsZero(), "an empty feed keeps the zero cursor")

	h.create(t, key(t, "tenant-a", "k1"))
	h.create(t, key(t, "tenant-b", "k1"))
	list, c1 := h.changes(t, store.Cursor{})
	require.Len(t, list, 2)
	require.True(t, c1.After(c0))
	again, c1b := h.changes(t, c1)
	require.Empty(t, again)
	require.Equal(t, c1, c1b, "nothing new keeps the cursor")

	h.put(t, key(t, "tenant-a", "k2"))
	h.put(t, key(t, "tenant-a", "k3"))
	list, c2 := h.changes(t, c1)
	require.Equal(t, []keys.Change{{Tenant: tenant(t, "tenant-a")}}, list, "a tenant appears once per poll")
	require.True(t, c2.After(c1), "cursors only move forward (T-15)")
	full, c2full := h.changes(t, store.Cursor{})
	require.Len(t, full, 2)
	require.Equal(t, c2, c2full)
}

func changesEveryMutation(t *testing.T, h *harness) {
	ctx := context.Background()
	a := tenant(t, "tenant-a")
	expect := func(step string, wantChange bool, cur store.Cursor) store.Cursor {
		t.Helper()
		list, next := h.changes(t, cur)
		if wantChange {
			require.Equal(t, []keys.Change{{Tenant: a}}, list, step)
			require.True(t, next.After(cur), step)
		} else {
			require.Empty(t, list, step)
			require.Equal(t, cur, next, step)
		}
		return next
	}
	cur := store.Cursor{}
	h.create(t, key(t, "tenant-a", "k1"))
	cur = expect("CreateTenant", true, cur)
	h.put(t, key(t, "tenant-a", "k2"))
	cur = expect("PutKey", true, cur)
	r := rotation(t, "tenant-a", "k2", "k3")
	r.Next.CreatedAt = now()
	require.NoError(t, h.s.Rotate(ctx, r))
	cur = expect("Rotate", true, cur)
	require.ErrorIs(t, h.s.PutKey(ctx, key(t, "tenant-a", "k2")), store.ErrConflict)
	cur = expect("a refused write", false, cur)
	require.NoError(t, h.s.RevokeTenantKeys(ctx, a))
	cur = expect("RevokeTenantKeys", true, cur)
	require.NoError(t, h.s.RevokeTenantKeys(ctx, a))
	cur = expect("RevokeTenantKeys with nothing to revoke", false, cur)
	h.create(t, key(t, "tenant-a", "k4"))
	cur = expect("CreateTenant after a revoke", true, cur)
	require.NoError(t, h.s.Tombstone(ctx, a))
	cur = expect("Tombstone", true, cur)
	require.NoError(t, h.s.Tombstone(ctx, a))
	expect("Tombstone twice", false, cur)

	b := tenant(t, "tenant-b")
	h.create(t, key(t, "tenant-b", "k1"))
	_, cur = h.changes(t, store.Cursor{})
	require.NoError(t, h.s.EraseTenant(ctx, b))
	list, _ := h.changes(t, cur)
	require.Equal(t, []keys.Change{{Tenant: b}}, list, "EraseTenant is in the feed")
}

func changesConcurrent(t *testing.T, h *harness) {
	ctx := context.Background()
	initial := make([]keys.Key, goroutines)
	for i := range initial {
		initial[i] = key(t, fmt.Sprintf("tenant-%d", i), "k1")
	}
	var failures atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			if err := h.s.CreateTenant(ctx, initial[i]); err != nil {
				failures.Add(1)
			}
		})
	}
	seen := map[string]struct{}{}
	done := make(chan struct{})
	var poll sync.WaitGroup
	poll.Go(func() {
		cur := store.Cursor{}
		for {
			list, next, err := h.s.ChangesSince(ctx, cur)
			if err != nil {
				return
			}
			cur = next
			for _, c := range list {
				seen[c.Tenant.String()] = struct{}{}
			}
			select {
			case <-done:
				list, _, err := h.s.ChangesSince(ctx, cur)
				if err == nil {
					for _, c := range list {
						seen[c.Tenant.String()] = struct{}{}
					}
				}
				return
			default:
			}
		}
	})
	close(start)
	wg.Wait()
	close(done)
	poll.Wait()
	require.Zero(t, failures.Load())
	require.Len(t, seen, goroutines, "a poller resuming from its cursors never misses a commit")
}

func changesPrunedGap(t *testing.T, h *harness) {
	ctx := context.Background()
	h.create(t, key(t, "tenant-a", "k1"))
	_, early := h.changes(t, store.Cursor{})
	require.NoError(t, h.s.RevokeTenantKeys(ctx, tenant(t, "tenant-a")))
	_, late := h.changes(t, early)
	h.f.AgeFeed(t, h.s, 48*time.Hour)
	h.create(t, key(t, "tenant-b", "k1"))
	_, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)

	list, next, err := h.s.ChangesSince(ctx, early)
	require.ErrorIs(t, err, store.ErrNotFound, "a cursor older than the pruned feed is refused, never answered with a gap")
	require.Empty(t, list)
	require.Equal(t, early, next)

	list, _ = h.changes(t, late)
	require.Equal(t, []keys.Change{{Tenant: tenant(t, "tenant-b")}}, list, "a cursor at the pruned horizon has no gap")
	list, fresh := h.changes(t, store.Cursor{})
	require.Equal(t, []keys.Change{{Tenant: tenant(t, "tenant-b")}}, list, "the zero cursor restarts from what is retained")
	again, _ := h.changes(t, fresh)
	require.Empty(t, again)
}

func reapRetiredForever(t *testing.T, h *harness) {
	ctx := context.Background()
	retired := key(t, "tenant-a", "retired-forever")
	ra := at(-time.Hour)
	retired.RetiredAt = &ra
	h.put(t, retired)
	h.put(t, key(t, "tenant-a", "live"))
	_, cur := h.changes(t, store.Cursor{})
	n, err := h.s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "a retired key without NotAfter never verifies, so it is reaped (X-16)")
	require.Equal(t, []string{"live"}, h.verifying(t, tenant(t, "tenant-a")))
	list, _ := h.changes(t, cur)
	require.Equal(t, []keys.Change{{Tenant: tenant(t, "tenant-a")}}, list)
}

func freshKEK(t *testing.T) *kek.Local {
	t.Helper()
	raw := make([]byte, kek.KeyLength)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	k, err := kek.NewLocal(raw)
	require.NoError(t, err)
	return k
}

func requireSealedBy(t *testing.T, k kek.KEK, ref sealing.Ref, ct []byte) {
	t.Helper()
	id, err := k.KeyIDOf(ct)
	require.NoError(t, err, "the stored bytes are a KEK ciphertext")
	require.Equal(t, k.CurrentKeyID(), id, "the stored bytes were sealed by this test's KEK and by nothing else")
	opened, err := sealing.Open(context.Background(), k, ref, ct)
	require.NoError(t, err, "the stored bytes were sealed through internal/sealing under the row's associated data")
	require.False(t, opened.Stale)
}

func sealedOpaque(t *testing.T, h *harness) {
	ctx := context.Background()
	k := freshKEK(t)
	key1 := key(t, "tenant-a", "k1")
	ref, err := sealing.SigningKey(key1.Tenant, key1.KeyID)
	require.NoError(t, err)
	plain := []byte("-----pkcs8-private-key-material-----")
	key1.Sealed, err = sealing.Seal(ctx, k, ref, plain)
	require.NoError(t, err)
	h.create(t, key1)

	got, err := h.s.ActiveKey(ctx, key1.Tenant)
	require.NoError(t, err)
	require.Equal(t, key1.Sealed, got.Sealed, "the store returns exactly the opaque bytes it was given")
	requireSealedBy(t, k, ref, got.Sealed)
	require.False(t, bytes.Contains(got.Sealed, plain), "the ciphertext is never the plaintext")
	opened, err := sealing.Open(ctx, k, ref, got.Sealed)
	require.NoError(t, err)
	require.Equal(t, plain, opened.Plaintext)

	elsewhere, err := sealing.SigningKey(tenant(t, "tenant-b"), "k1")
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, elsewhere, got.Sealed)
	require.Error(t, err, "another tenant's associated data fails")
	otherKey, err := sealing.SigningKey(key1.Tenant, "k2")
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, otherKey, got.Sealed)
	require.Error(t, err, "another key id's associated data fails")
}

type legacyFixtures struct {
	Key   string
	Cases []struct{ Name, AAD, Plaintext, Blob string }
}

func loadLegacy(t *testing.T) (kek.LegacyOpener, map[string][2][]byte) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "kek", "testdata", "v016_fixtures.json"))
	require.NoError(t, err)
	var f legacyFixtures
	require.NoError(t, json.Unmarshal(raw, &f))
	keyBytes, err := hex.DecodeString(f.Key)
	require.NoError(t, err)
	opener, err := kek.LegacyLocalV016(keyBytes)
	require.NoError(t, err)
	out := map[string][2][]byte{}
	for _, c := range f.Cases {
		blob, err := hex.DecodeString(c.Blob)
		require.NoError(t, err)
		pt, err := hex.DecodeString(c.Plaintext)
		require.NoError(t, err)
		out[c.Name] = [2][]byte{blob, pt}
	}
	return opener, out
}

func legacyOf(k keys.Key, sealed []byte) keys.Key {
	k.Sealed = sealed
	k.AADVersion = keys.AADVersionLegacy
	return k
}

type legacyRow struct {
	key       keys.Key
	plaintext []byte
}

func seedLegacy(t *testing.T, h *harness) []legacyRow {
	t.Helper()
	_, cases := loadLegacy(t)
	rows := []legacyRow{
		{key: legacyOf(key(t, "tenant-a", "hs"), cases["keystore_keys tenant"][0]), plaintext: cases["keystore_keys tenant"][1]},
		{key: legacyOf(key(t, "tenant-z", "pem"), cases["no aad"][0]), plaintext: cases["no aad"][1]},
		{key: legacyOf(key(t, "tenant-a", "broken"), bytes.Repeat([]byte{7}, 64))},
	}
	for _, r := range rows {
		h.f.SeedV016(t, h.s, r.key)
	}
	return rows
}

func legacyUpgrade(t *testing.T, h *harness) {
	ctx := context.Background()
	legacy, _ := loadLegacy(t)
	rows := seedLegacy(t, h)
	h.create(t, key(t, "tenant-b", "fresh"))

	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, len(rows), n, "only aad_version 0 rows are legacy")

	var listed []keys.V016Row
	cur := store.Cursor{}
	for {
		page, next, err := h.s.V016Sealed(ctx, cur, 2)
		require.NoError(t, err)
		if len(page) == 0 {
			require.Equal(t, cur, next, "an empty page keeps the cursor")
			break
		}
		require.LessOrEqual(t, len(page), 2)
		require.True(t, next.After(cur), "the cursor is monotonic")
		listed = append(listed, page...)
		cur = next
	}
	require.Len(t, listed, len(rows), "every legacy row is listed exactly once")
	_, _, err = h.s.V016Sealed(ctx, store.Cursor{}, 0)
	require.Error(t, err)

	byRef := map[keys.SealedRef]keys.V016Row{}
	for _, r := range listed {
		byRef[r.Ref] = r
	}
	require.NotContains(t, byRef, keys.SealedRef{Tenant: tenant(t, "tenant-b"), KeyID: "fresh"})

	k := freshKEK(t)
	reported := 0
	for _, want := range rows {
		ref := keys.SealedRef{Tenant: want.key.Tenant, KeyID: want.key.KeyID}
		got, ok := byRef[ref]
		require.True(t, ok)
		require.Equal(t, want.key.Sealed, got.Sealed)
		sref, err := sealing.SigningKey(ref.Tenant, ref.KeyID)
		require.NoError(t, err)
		pt, err := sealing.OpenLegacy(ctx, legacy, sref, got.Sealed)
		if want.plaintext == nil {
			require.ErrorIs(t, err, sealing.ErrLegacyUnopenable, "a row that opens under no candidate is reported, not skipped")
			reported++
			continue
		}
		require.NoError(t, err)
		require.Equal(t, want.plaintext, pt)
		ct, err := sealing.Seal(ctx, k, sref, pt)
		require.NoError(t, err)
		ok, err = h.s.ReplaceSealed(ctx, keys.Reseal{Ref: ref, Old: got.Sealed, New: ct})
		require.NoError(t, err)
		require.True(t, ok)
		opened := h.find(t, ref)
		require.Equal(t, keys.AADVersionCurrent, opened.AADVersion)
		requireSealedBy(t, k, sref, opened.Sealed)
		require.False(t, bytes.Contains(opened.Sealed, want.plaintext), "the converted ciphertext is never the plaintext")
		plain, err := sealing.Open(ctx, k, sref, opened.Sealed)
		require.NoError(t, err)
		require.Equal(t, want.plaintext, plain.Plaintext, "the converted key opens under the v0.17 AAD")
	}
	require.Equal(t, 1, reported)
	n, err = h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "only the unopenable row remains")
}

func (h *harness) find(t *testing.T, ref keys.SealedRef) keys.Key {
	t.Helper()
	list, err := h.s.VerificationKeys(context.Background(), ref.Tenant)
	require.NoError(t, err)
	for _, k := range list {
		if k.KeyID == ref.KeyID {
			return k
		}
	}
	t.Fatalf("key %s not found", ref.KeyID)
	return keys.Key{}
}

func replaceSealedCAS(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	ref := keys.SealedRef{Tenant: rows[0].key.Tenant, KeyID: rows[0].key.KeyID}
	before := h.find(t, ref)
	require.Equal(t, keys.AADVersionLegacy, before.AADVersion)

	ok, err := h.s.ReplaceSealed(ctx, keys.Reseal{Ref: ref, Old: []byte("stale"), New: []byte("new")})
	require.NoError(t, err)
	require.False(t, ok, "material replaced in the meantime is never overwritten")
	require.Equal(t, before, h.find(t, ref))

	ok, err = h.s.ReplaceSealed(ctx, keys.Reseal{Ref: keys.SealedRef{Tenant: ref.Tenant, KeyID: "ghost"}, Old: before.Sealed, New: []byte("new")})
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = h.s.ReplaceSealed(ctx, keys.Reseal{Ref: keys.SealedRef{Tenant: tenant(t, "tenant-other"), KeyID: ref.KeyID}, Old: before.Sealed, New: []byte("new")})
	require.NoError(t, err)
	require.False(t, ok, "the reference is scoped to its tenant")

	_, cur := h.changes(t, store.Cursor{})
	ok, err = h.s.ReplaceSealed(ctx, keys.Reseal{Ref: ref, Old: before.Sealed, New: []byte("resealed")})
	require.NoError(t, err)
	require.True(t, ok)
	after := h.find(t, ref)
	require.Equal(t, []byte("resealed"), after.Sealed)
	require.Equal(t, keys.AADVersionCurrent, after.AADVersion)
	before.Sealed, before.AADVersion = after.Sealed, after.AADVersion
	require.Equal(t, before, after, "ReplaceSealed changes no other field of the key")
	list, _ := h.changes(t, cur)
	require.Empty(t, list, "a re-seal does not change what verifies")

	for name, r := range map[string]keys.Reseal{
		"empty new": {Ref: ref, Old: after.Sealed},
		"empty old": {Ref: ref, New: []byte("x")},
		"no ref":    {Old: after.Sealed, New: []byte("x")},
	} {
		ok, err := h.s.ReplaceSealed(ctx, r)
		require.Error(t, err, name)
		require.False(t, ok, name)
	}
}

func replaceSealedRace(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	ref := keys.SealedRef{Tenant: rows[0].key.Tenant, KeyID: rows[0].key.KeyID}
	old := h.find(t, ref).Sealed
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			ok, err := h.s.ReplaceSealed(ctx, keys.Reseal{Ref: ref, Old: old, New: []byte{byte(i), 1, 2, 3}})
			if err == nil && ok {
				wins.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "exactly one concurrent re-seal wins the compare-and-swap")
}
