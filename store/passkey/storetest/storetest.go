// Package storetest holds the conformance suite of passkey.Store implementations. The store embeds
// store.Base only: credentials carry no expiry, so there is no Reaper to assert.
package storetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/passkey"
)

const goroutines = 16

// Fixtures is what the store implementation's test hands the suite through Seed.
type Fixtures struct {
	// SeedV016 inserts c with DiscoverableState Legacy, the way a v0.16 deployment left it. Stores
	// refuse a Legacy credential through Save, so each implementation provides its own.
	SeedV016 func(t *testing.T, s passkey.Store, c passkey.Credential)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the passkey.Store contract against stores returned by newStore. Each subtest gets a
// fresh, empty store. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) passkey.Store) {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, Fixtures{...}) before Run")
	}
	f := v.(Fixtures)
	if f.SeedV016 == nil {
		t.Fatal("storetest: Fixtures.SeedV016 is required")
	}
	suites := map[string]func(*testing.T, passkey.Store){
		"Base":                  baseSuite,
		"CredentialIDJSON":      credentialIDJSON,
		"CredentialJSONListing": credentialJSONListing,
		"SaveGetList":           saveGetList,
		"SaveRefusals":          saveRefusals,
		"SaveConflictRace":      saveConflictRace,
		"RawIDsRoundTrip":       rawIDs,
		"DiscoverableState":     discoverableState,
		"LegacyRows":            func(t *testing.T, s passkey.Store) { legacyRows(t, s, f) },
		"SingleTenant":          singleTenant,
		"Update":                update,
		"UpdateSignCount":       updateSignCount,
		"SignCountRace":         signCountRace,
		"CloneSuspension":       cloneSuspension,
		"HasActive":             hasActive,
		"EnrolledCounts":        enrolledCounts,
		"Delete":                deleteOne,
		"DeleteForSubject":      deleteForSubject,
		"EraseTenant":           eraseTenant,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

var base = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func tenant(t *testing.T, name string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(name)
	require.NoError(t, err)
	return id
}

func subjectIn(t *testing.T, tn string) principal.Subject {
	t.Helper()
	return principal.Subject{Tenant: tenant(t, tn), User: uuid.New()}
}

func cred(sub principal.Subject, id string) passkey.Credential {
	return passkey.Credential{
		Subject: sub, ID: passkey.CredentialID(id), PublicKey: []byte("pk-" + id), Data: []byte("data-" + id),
		CreatedAt: base, Nickname: "laptop", Discoverable: passkey.Confirmed,
	}
}

func requireCred(t *testing.T, want, got passkey.Credential) {
	t.Helper()
	require.Equal(t, want.Subject, got.Subject)
	require.True(t, want.ID.Equal(got.ID))
	require.Equal(t, want.PublicKey, got.PublicKey)
	require.Equal(t, want.SignCount, got.SignCount)
	require.Equal(t, want.Data, got.Data)
	require.True(t, want.CreatedAt.Equal(got.CreatedAt))
	require.Equal(t, want.Nickname, got.Nickname)
	requireTime(t, want.LastUsedAt, got.LastUsedAt)
	require.Equal(t, want.Transports, got.Transports)
	require.Equal(t, want.BackupEligible, got.BackupEligible)
	require.Equal(t, want.BackupState, got.BackupState)
	require.Equal(t, want.Discoverable, got.Discoverable)
	requireTime(t, want.SuspendedAt, got.SuspendedAt)
}

func requireTime(t *testing.T, want, got *time.Time) {
	t.Helper()
	if want == nil {
		require.Nil(t, got)
		return
	}
	require.NotNil(t, got)
	require.True(t, want.Equal(*got), "want %v, got %v", want, got)
}

func get(t *testing.T, s passkey.Store, sub principal.Subject, id string) passkey.Credential {
	t.Helper()
	c, err := s.Get(context.Background(), sub.Tenant, passkey.CredentialID(id))
	require.NoError(t, err)
	return c
}

func baseSuite(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	require.NoError(t, s.Ping(ctx))
	require.True(t, s.Durability().Valid())
	require.NoError(t, s.EraseTenant(ctx, principal.TenantID{}))
}

func credentialIDJSON(t *testing.T, _ passkey.Store) {
	raw := passkey.CredentialID{0xfb, 0xff, 0xfe, 0x00, 0x01}
	b, err := json.Marshal(raw)
	require.NoError(t, err)
	require.Equal(t, `"-__-AAE"`, string(b), "unpadded base64url, the alphabet of the wire and of the logs")
	require.Equal(t, "-__-AAE", raw.String())

	var back passkey.CredentialID
	require.NoError(t, json.Unmarshal(b, &back))
	require.True(t, raw.Equal(back))

	var holder struct{ ID passkey.CredentialID }
	require.NoError(t, json.Unmarshal([]byte(`{"ID":null}`), &holder))
	require.Empty(t, holder.ID, "null leaves the id unchanged")
	empty, err := json.Marshal(passkey.CredentialID(nil))
	require.NoError(t, err)
	require.Equal(t, "null", string(empty))

	for name, in := range map[string]string{
		"padded":        `"-__-AAE="`,
		"standard":      `"+//+AAE"`,
		"empty":         `""`,
		"number":        `12`,
		"object":        `{}`,
		"trailing bits": `"-__-AAF"`,
		"space":         `"-__ -AAE"`,
		"too long":      `"` + strings.Repeat("A", 1400+1) + `"`,
	} {
		var c passkey.CredentialID
		require.Error(t, json.Unmarshal([]byte(in), &c), name)
	}
	max := bytes.Repeat([]byte{0x41}, passkey.MaxCredentialIDLen)
	b, err = json.Marshal(passkey.CredentialID(max))
	require.NoError(t, err)
	var ok passkey.CredentialID
	require.NoError(t, json.Unmarshal(b, &ok), "the WebAuthn bound itself is accepted")
	over, err := json.Marshal(passkey.CredentialID(append(max, 0x41)))
	require.NoError(t, err)
	require.Error(t, json.Unmarshal(over, &ok))
}

func credentialJSONListing(t *testing.T, _ passkey.Store) {
	suspended := base.Add(time.Hour)
	c := cred(subjectIn(t, "tenant-a"), "id-1")
	c.SignCount = 9
	c.SuspendedAt = &suspended
	b, err := json.Marshal(c)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	for _, hidden := range []string{"Subject", "PublicKey", "SignCount", "Data", "subject", "public_key", "sign_count", "data"} {
		require.NotContains(t, m, hidden, "the listing never carries %s", hidden)
	}
	require.Equal(t, passkey.CredentialID("id-1").String(), m["id"])
	require.EqualValues(t, passkey.Confirmed, m["discoverable"])
	require.Contains(t, m, "suspended_at")
}

func saveGetList(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	used := base.Add(time.Minute)
	full := cred(sub, "full")
	full.SignCount = 4
	full.LastUsedAt = &used
	full.Transports = []string{"usb", "nfc"}
	full.BackupEligible, full.BackupState = true, true
	full.Discoverable = passkey.Inferred
	require.NoError(t, s.Save(ctx, full))
	requireCred(t, full, get(t, s, sub, "full"))

	second := cred(sub, "second")
	second.CreatedAt = base.Add(time.Hour)
	require.NoError(t, s.Save(ctx, second))
	other := cred(subjectIn(t, "tenant-a"), "other-user")
	require.NoError(t, s.Save(ctx, other))

	list, err := s.List(ctx, sub)
	require.NoError(t, err)
	require.Len(t, list, 2)
	byID := map[string]passkey.Credential{}
	for _, c := range list {
		byID[c.ID.String()] = c
		require.Equal(t, sub, c.Subject)
	}
	requireCred(t, full, byID[full.ID.String()])
	requireCred(t, second, byID[second.ID.String()])

	list, err = s.List(ctx, subjectIn(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, list)

	_, err = s.Get(ctx, sub.Tenant, passkey.CredentialID("unknown"))
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.Get(ctx, tenant(t, "tenant-b"), full.ID)
	require.ErrorIs(t, err, store.ErrNotFound, "credential ids are scoped to their tenant")

	got := get(t, s, sub, "full")
	got.PublicKey[0] = 'X'
	got.Transports[0] = "X"
	requireCred(t, full, get(t, s, sub, "full"))
}

func saveRefusals(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, s.Save(ctx, cred(sub, "dup")))
	err := s.Save(ctx, cred(subjectIn(t, "tenant-a"), "dup"))
	require.ErrorIs(t, err, store.ErrConflict, "an id is unique per tenant, whoever owns it")
	require.NoError(t, s.Save(ctx, cred(subjectIn(t, "tenant-b"), "dup")), "another tenant may reuse the id")
	require.Equal(t, sub, get(t, s, sub, "dup").Subject)

	for name, c := range map[string]passkey.Credential{
		"zero subject": cred(principal.Subject{}, "a"),
		"empty id":     cred(sub, ""),
		"oversized id": func() passkey.Credential {
			c := cred(sub, "a")
			c.ID = bytes.Repeat([]byte{1}, passkey.MaxCredentialIDLen+1)
			return c
		}(),
		"no public key": func() passkey.Credential { c := cred(sub, "a"); c.PublicKey = nil; return c }(),
		"unknown state": func() passkey.Credential { c := cred(sub, "a"); c.Discoverable = 9; return c }(),
		"legacy state":  func() passkey.Credential { c := cred(sub, "a"); c.Discoverable = passkey.Legacy; return c }(),
	} {
		err := s.Save(ctx, c)
		require.Error(t, err, name)
		require.NotErrorIs(t, err, store.ErrConflict, name)
	}
	list, err := s.List(ctx, sub)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func saveConflictRace(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	tn := tenant(t, "tenant-a")
	for range goroutines {
		wg.Go(func() {
			switch err := s.Save(ctx, cred(principal.Subject{Tenant: tn, User: uuid.New()}, "same")); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrConflict):
				conflicts.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
	require.EqualValues(t, goroutines-1, conflicts.Load())
}

func rawIDs(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	ids := [][]byte{{0x00}, {0xff, 0x00, 0xff}, bytes.Repeat([]byte{0xab}, passkey.MaxCredentialIDLen), []byte("with'quote")}
	for _, id := range ids {
		c := cred(sub, "x")
		c.ID = id
		require.NoError(t, s.Save(ctx, c))
	}
	for _, id := range ids {
		got, err := s.Get(ctx, sub.Tenant, id)
		require.NoError(t, err)
		require.True(t, got.ID.Equal(id))
	}
	_, err := s.Get(ctx, sub.Tenant, []byte{0xff, 0x00})
	require.ErrorIs(t, err, store.ErrNotFound, "ids compare byte for byte, never as a prefix or as text")
}

func discoverableState(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	for _, st := range []passkey.DiscoverableState{passkey.Confirmed, passkey.Inferred} {
		c := cred(sub, st.String())
		c.Discoverable = st
		require.NoError(t, s.Save(ctx, c))
		require.Equal(t, st, get(t, s, sub, st.String()).Discoverable)
	}

	fresh := cred(sub, "legacy")
	fresh.Discoverable = passkey.Legacy
	err := s.Save(ctx, fresh)
	require.Error(t, err, "Legacy is reserved for v0.16 rows, never written for a new credential")
	require.NotErrorIs(t, err, store.ErrConflict)
	_, err = s.Get(ctx, sub.Tenant, fresh.ID)
	require.ErrorIs(t, err, store.ErrNotFound, "a refused save leaves nothing behind")

	c := get(t, s, sub, "inferred")
	c.Discoverable = passkey.Confirmed
	require.NoError(t, s.Update(ctx, c))
	require.Equal(t, passkey.Confirmed, get(t, s, sub, "inferred").Discoverable)
	c.Discoverable = passkey.Legacy
	c.Nickname = "downgrade"
	require.NoError(t, s.Update(ctx, c))
	got := get(t, s, sub, "inferred")
	require.Equal(t, passkey.Confirmed, got.Discoverable, "Update never downgrades a credential to Legacy")
	require.Equal(t, "downgrade", got.Nickname)
	c.Discoverable = 9
	require.Error(t, s.Update(ctx, c))
	require.Equal(t, passkey.Confirmed, get(t, s, sub, "inferred").Discoverable)
}

func legacyRows(t *testing.T, s passkey.Store, f Fixtures) {
	ctx := context.Background()
	for name, sub := range map[string]principal.Subject{
		"tenant":        subjectIn(t, "tenant-a"),
		"single tenant": {User: uuid.New()},
	} {
		c := cred(sub, "v016-"+name)
		c.Discoverable = passkey.Legacy
		f.SeedV016(t, s, c)
		got := get(t, s, sub, string(c.ID))
		require.Equal(t, sub, got.Subject, name)
		require.Equal(t, passkey.Legacy, got.Discoverable, name)
		require.True(t, got.Discoverable.NeedsReregistration(), name)
		ok, err := s.HasActive(ctx, sub)
		require.NoError(t, err)
		require.True(t, ok, "%s: a v0.16 credential still authenticates until re-registered", name)

		got.Nickname = "renamed"
		require.NoError(t, s.Update(ctx, got), "%s: a v0.16 credential can be renamed as read", name)
		got = get(t, s, sub, string(c.ID))
		require.Equal(t, "renamed", got.Nickname, name)
		require.Equal(t, passkey.Legacy, got.Discoverable, name)

		got.Discoverable = passkey.Confirmed
		require.NoError(t, s.Update(ctx, got))
		require.Equal(t, passkey.Confirmed, get(t, s, sub, string(c.ID)).Discoverable, name)
	}
}

func singleTenant(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	single := principal.Subject{User: uuid.New()}
	tenanted := principal.Subject{Tenant: tenant(t, "tenant-a"), User: single.User}
	require.NoError(t, s.Save(ctx, cred(single, "same")))
	require.NoError(t, s.Save(ctx, cred(tenanted, "same")), "the single tenant is a tenant of its own")
	requireCred(t, cred(single, "same"), get(t, s, single, "same"))
	list, err := s.List(ctx, single)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, single, list[0].Subject)
	ok, err := s.UpdateSignCount(ctx, single, passkey.CredentialID("same"), 3)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, get(t, s, tenanted, "same").SignCount, "the same user under a tenant is another subject")

	require.NoError(t, s.EraseTenant(ctx, principal.TenantID{}))
	_, err = s.Get(ctx, principal.TenantID{}, passkey.CredentialID("same"))
	require.ErrorIs(t, err, store.ErrNotFound)
	get(t, s, tenanted, "same")
}

func update(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	orig := cred(sub, "u")
	orig.SignCount = 7
	require.NoError(t, s.Save(ctx, orig))
	suspendedAt := base.Add(time.Hour)
	require.NoError(t, s.Suspend(ctx, sub, orig.ID, suspendedAt))

	used := base.Add(2 * time.Hour)
	change := orig
	change.Nickname = "renamed"
	change.LastUsedAt = &used
	change.Transports = []string{"internal"}
	change.BackupEligible, change.BackupState = true, true
	change.Discoverable = passkey.Inferred
	change.SignCount = 1000
	change.SuspendedAt = nil
	change.PublicKey = []byte("swapped")
	change.CreatedAt = base.Add(99 * time.Hour)
	require.NoError(t, s.Update(ctx, change))

	got := get(t, s, sub, "u")
	require.Equal(t, "renamed", got.Nickname)
	requireTime(t, &used, got.LastUsedAt)
	require.Equal(t, []string{"internal"}, got.Transports)
	require.True(t, got.BackupEligible && got.BackupState)
	require.Equal(t, passkey.Inferred, got.Discoverable)
	require.EqualValues(t, 7, got.SignCount, "Update never changes the counter")
	requireTime(t, &suspendedAt, got.SuspendedAt)
	require.Equal(t, orig.PublicKey, got.PublicKey)
	require.True(t, orig.CreatedAt.Equal(got.CreatedAt))
	require.Equal(t, sub, got.Subject)

	stranger := change
	stranger.Subject = subjectIn(t, "tenant-a")
	require.ErrorIs(t, s.Update(ctx, stranger), store.ErrNotFound, "Update is scoped to the subject")
	require.Equal(t, "renamed", get(t, s, sub, "u").Nickname)
	missing := change
	missing.ID = passkey.CredentialID("missing")
	require.ErrorIs(t, s.Update(ctx, missing), store.ErrNotFound)
}

func updateSignCount(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	c := cred(sub, "sc")
	c.SignCount = 5
	require.NoError(t, s.Save(ctx, c))
	count := func() uint32 { return get(t, s, sub, "sc").SignCount }
	try := func(next uint32) bool {
		ok, err := s.UpdateSignCount(ctx, sub, c.ID, next)
		require.NoError(t, err)
		return ok
	}
	require.True(t, try(6))
	require.EqualValues(t, 6, count())
	require.False(t, try(6), "an equal counter is the clone signal")
	require.False(t, try(5))
	require.False(t, try(0), "zero against a non-zero counter is the clone signal too")
	require.EqualValues(t, 6, count(), "a false result stores nothing")
	require.True(t, try(4000000000))
	require.True(t, try(4294967295))
	require.False(t, try(4294967295))

	flat := cred(sub, "flat")
	require.NoError(t, s.Save(ctx, flat))
	ok, err := s.UpdateSignCount(ctx, sub, flat.ID, 0)
	require.NoError(t, err)
	require.True(t, ok, "zero against zero is an authenticator without a counter")
	ok, err = s.UpdateSignCount(ctx, sub, flat.ID, 1)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = s.UpdateSignCount(ctx, sub, passkey.CredentialID("missing"), 1)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.UpdateSignCount(ctx, subjectIn(t, "tenant-a"), c.ID, 9)
	require.ErrorIs(t, err, store.ErrNotFound, "scoped to the subject")
	require.EqualValues(t, 4294967295, count())
}

func signCountRace(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, s.Save(ctx, cred(sub, "race")))
	id := passkey.CredentialID("race")
	var wg sync.WaitGroup
	oks := make([]atomic.Bool, goroutines+1)
	for next := uint32(1); next <= goroutines; next++ {
		wg.Go(func() {
			ok, err := s.UpdateSignCount(ctx, sub, id, next)
			if err == nil {
				oks[next].Store(ok)
			}
		})
	}
	wg.Wait()
	require.True(t, oks[goroutines].Load(), "the greatest counter beats whatever a concurrent ceremony stored")
	require.EqualValues(t, goroutines, get(t, s, sub, "race").SignCount)
}

func cloneSuspension(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	c := cred(sub, "clone")
	c.SignCount = 10
	require.NoError(t, s.Save(ctx, c))
	keep := cred(sub, "keep")
	require.NoError(t, s.Save(ctx, keep))

	ok, err := s.UpdateSignCount(ctx, sub, c.ID, 3)
	require.NoError(t, err)
	require.False(t, ok)
	at := base.Add(time.Hour)
	require.NoError(t, s.Suspend(ctx, sub, c.ID, at))

	got := get(t, s, sub, "clone")
	requireTime(t, &at, got.SuspendedAt)
	require.False(t, got.Active())
	require.EqualValues(t, 10, got.SignCount)
	require.Equal(t, c.Data, got.Data, "the credential is never deleted")
	list, err := s.List(ctx, sub)
	require.NoError(t, err)
	require.Len(t, list, 2, "suspended credentials are still listed")

	require.NoError(t, s.Suspend(ctx, sub, c.ID, at.Add(time.Hour)))
	requireTime(t, &at, get(t, s, sub, "clone").SuspendedAt)

	require.ErrorIs(t, s.Suspend(ctx, sub, passkey.CredentialID("missing"), at), store.ErrNotFound)
	require.ErrorIs(t, s.Suspend(ctx, subjectIn(t, "tenant-a"), keep.ID, at), store.ErrNotFound)
	require.True(t, get(t, s, sub, "keep").Active())
}

func hasActive(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	has := func() bool {
		ok, err := s.HasActive(ctx, sub)
		require.NoError(t, err)
		return ok
	}
	require.False(t, has())
	require.NoError(t, s.Save(ctx, cred(sub, "one")))
	require.True(t, has())
	require.NoError(t, s.Suspend(ctx, sub, passkey.CredentialID("one"), base))
	require.False(t, has(), "a suspended credential never makes the subject enrolled")
	require.NoError(t, s.Save(ctx, cred(sub, "two")))
	require.True(t, has())
	require.NoError(t, s.Delete(ctx, sub, passkey.CredentialID("two")))
	require.False(t, has())

	stranger := subjectIn(t, "tenant-a")
	require.NoError(t, s.Save(ctx, cred(stranger, "theirs")))
	require.False(t, has(), "another subject's credential does not count")
}

func enrolledCounts(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	counts := func() (bool, int64) {
		any, err := s.AnyEnrolled(ctx)
		require.NoError(t, err)
		n, err := s.CountEnrolled(ctx)
		require.NoError(t, err)
		return any, n
	}
	any, n := counts()
	require.False(t, any)
	require.Zero(t, n)

	a, b := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-b")
	require.NoError(t, s.Save(ctx, cred(a, "a1")))
	require.NoError(t, s.Save(ctx, cred(a, "a2")))
	any, n = counts()
	require.True(t, any)
	require.EqualValues(t, 1, n, "subjects are counted, not credentials")
	require.NoError(t, s.Save(ctx, cred(b, "b1")))
	require.NoError(t, s.Suspend(ctx, b, passkey.CredentialID("b1"), base))
	_, n = counts()
	require.EqualValues(t, 2, n, "a suspended credential still counts as enrolled")

	require.NoError(t, s.DeleteForSubject(ctx, a))
	require.NoError(t, s.Delete(ctx, b, passkey.CredentialID("b1")))
	any, n = counts()
	require.False(t, any)
	require.Zero(t, n)
}

func deleteOne(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	sub := subjectIn(t, "tenant-a")
	require.NoError(t, s.Save(ctx, cred(sub, "d1")))
	require.NoError(t, s.Save(ctx, cred(sub, "d2")))
	stranger := subjectIn(t, "tenant-a")
	require.ErrorIs(t, s.Delete(ctx, stranger, passkey.CredentialID("d1")), store.ErrNotFound, "only the owner deletes")
	get(t, s, sub, "d1")
	require.NoError(t, s.Delete(ctx, sub, passkey.CredentialID("d1")))
	require.ErrorIs(t, s.Delete(ctx, sub, passkey.CredentialID("d1")), store.ErrNotFound)
	_, err := s.Get(ctx, sub.Tenant, passkey.CredentialID("d1"))
	require.ErrorIs(t, err, store.ErrNotFound)
	get(t, s, sub, "d2")
	require.NoError(t, s.Save(ctx, cred(stranger, "d1")), "the id is free again")
}

func deleteForSubject(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	gone, kept := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-a")
	require.NoError(t, s.Save(ctx, cred(gone, "g1")))
	require.NoError(t, s.Save(ctx, cred(gone, "g2")))
	require.NoError(t, s.Save(ctx, cred(kept, "k1")))
	require.NoError(t, s.DeleteForSubject(ctx, gone))
	require.NoError(t, s.DeleteForSubject(ctx, gone), "idempotent")
	list, err := s.List(ctx, gone)
	require.NoError(t, err)
	require.Empty(t, list)
	get(t, s, kept, "k1")
}

func eraseTenant(t *testing.T, s passkey.Store) {
	ctx := context.Background()
	a, b := subjectIn(t, "tenant-a"), subjectIn(t, "tenant-b")
	require.NoError(t, s.Save(ctx, cred(a, "x")))
	require.NoError(t, s.Save(ctx, cred(b, "x")))
	require.NoError(t, s.EraseTenant(ctx, a.Tenant))
	_, err := s.Get(ctx, a.Tenant, passkey.CredentialID("x"))
	require.ErrorIs(t, err, store.ErrNotFound)
	get(t, s, b, "x")
	n, err := s.CountEnrolled(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}
