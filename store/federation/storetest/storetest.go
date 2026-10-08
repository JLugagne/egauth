// Package storetest holds the conformance suite of federation.Store implementations.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/federation"
)

const goroutines = 32

// Fixtures is what the store implementation's test hands the suite through Seed. Every function
// reaches state the federation.Store contract cannot write: accounts and links belong to the identity
// store s reads its links from, and stores refuse a v0.16 secret through PutProvider.
type Fixtures struct {
	// SeedV016 inserts p, whose AADVersion is AADVersionLegacy, the way a v0.16 deployment left it.
	SeedV016 func(t *testing.T, s federation.Store, p federation.ProviderSpec)
	// NewAccount creates a live account of tenant tn holding a password credential whose provider
	// subject is the user id, and returns its subject.
	NewAccount func(t *testing.T, s federation.Store, tn principal.TenantID) principal.Subject
	// SeedLink links l.Key to l.Subject, an account NewAccount returned, as the identity store's
	// LinkFederated does, with l.LinkedAt as the link time. A backend whose identity store refuses l,
	// such as a verified flag without an email that a v0.16 row can hold, seeds the nearest state it
	// accepts.
	SeedLink func(t *testing.T, s federation.Store, l federation.LinkedIdentity)
	// Tombstone marks the account deleted, as the identity store's Tombstone mutation does.
	Tombstone func(t *testing.T, s federation.Store, sub principal.Subject)
}

var fixtures sync.Map

// Seed hands Run, for t and its subtests, the fixtures it needs. Call it before Run on the same t.
func Seed(t *testing.T, f Fixtures) {
	t.Helper()
	fixtures.Store(t, f)
	t.Cleanup(func() { fixtures.Delete(t) })
}

// Run exercises the federation.Store contract against stores returned by newStore. Each subtest
// gets a fresh, empty store. Run fails t unless Seed was called on it.
func Run(t *testing.T, newStore func(*testing.T) federation.Store) {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("storetest: call Seed(t, Fixtures{...}) before Run")
	}
	f := v.(Fixtures)
	if f.SeedV016 == nil || f.NewAccount == nil || f.SeedLink == nil || f.Tombstone == nil {
		t.Fatal("storetest: every Fixtures field is required")
	}
	suites := map[string]func(*testing.T, *harness){
		"Base":                  baseSuite,
		"ProviderRoundTrip":     providerRoundTrip,
		"PutRefusals":           putRefusals,
		"PutReplaces":           putReplaces,
		"ProviderIsolation":     providerIsolation,
		"ListProviders":         listProviders,
		"DeleteProvider":        deleteProvider,
		"EmailVerification":     emailVerification,
		"Links":                 links,
		"PasswordIsNeverALink":  passwordIsNeverALink,
		"UnverifiedEmail":       unverifiedEmail,
		"TombstonedAccount":     tombstonedAccount,
		"DeleteForSubject":      deleteForSubject,
		"EraseTenant":           eraseTenant,
		"SealedOpaque":          sealedOpaque,
		"LegacyUpgrade":         legacyUpgrade,
		"ReplaceSealedCAS":      replaceSealedCAS,
		"ReplaceSealedRace":     replaceSealedRace,
		"ReplaceSealedRefusals": replaceSealedRefusals,
	}
	for name, fn := range suites {
		t.Run(name, func(t *testing.T) { fn(t, &harness{s: newStore(t), f: f}) })
	}
}

type harness struct {
	s federation.Store
	f Fixtures
}

func linkBase() time.Time {
	return clock.Clock{}.Now().UTC().Truncate(time.Microsecond).Add(-48 * time.Hour)
}

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

func (h *harness) account(t *testing.T, tn string) principal.Subject {
	t.Helper()
	return h.f.NewAccount(t, h.s, tenant(t, tn))
}

func spec(t *testing.T, tn, name string) federation.ProviderSpec {
	t.Helper()
	return federation.ProviderSpec{
		Tenant:            tenant(t, tn),
		Name:              name,
		ClientID:          "client-" + name,
		SealedSecret:      []byte("sealed-" + tn + "-" + name),
		AADVersion:        federation.AADVersionCurrent,
		AuthURL:           "https://idp.example.com/authorize",
		TokenURL:          "https://idp.example.com/token",
		UserInfoURL:       "https://idp.example.com/userinfo",
		Scopes:            []string{"openid", "email", "profile"},
		Issuer:            "https://idp.example.com",
		JWKSURL:           "https://idp.example.com/jwks",
		Domains:           []string{"example.com", "example.org"},
		EmailVerification: federation.ClaimBased,
	}
}

func (h *harness) put(t *testing.T, p federation.ProviderSpec) {
	t.Helper()
	require.NoError(t, h.s.PutProvider(context.Background(), p))
}

func (h *harness) get(t *testing.T, tn principal.TenantID, name string) federation.ProviderSpec {
	t.Helper()
	p, err := h.s.GetProvider(context.Background(), tn, name)
	require.NoError(t, err)
	return p
}

func withoutStamp(p federation.ProviderSpec) federation.ProviderSpec {
	p.UpdatedAt = time.Time{}
	return p
}

func requireStamped(t *testing.T, p federation.ProviderSpec) {
	t.Helper()
	require.WithinDuration(t, clock.Clock{}.Now(), p.UpdatedAt, time.Minute, "UpdatedAt is the store's write time")
	require.Equal(t, time.UTC, p.UpdatedAt.Location())
}

func baseSuite(t *testing.T, h *harness) {
	ctx := context.Background()
	require.NoError(t, h.s.Ping(ctx))
	require.True(t, h.s.Durability().Valid())
	require.NoError(t, h.s.EraseTenant(ctx, tenant(t, "nobody")))
	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}

func providerRoundTrip(t *testing.T, h *harness) {
	ctx := context.Background()
	want := spec(t, "tenant-a", "corp")
	h.put(t, want)
	got := h.get(t, want.Tenant, "corp")
	requireStamped(t, got)
	require.Equal(t, withoutStamp(want), withoutStamp(got), "every field of the spec round-trips")

	bare := federation.ProviderSpec{
		Tenant: want.Tenant, Name: "bare", ClientID: "c", SealedSecret: []byte("x"),
		AADVersion: federation.AADVersionCurrent, AuthURL: "https://a", TokenURL: "https://t",
	}
	h.put(t, bare)
	got = h.get(t, want.Tenant, "bare")
	require.Empty(t, got.Scopes)
	require.Empty(t, got.Domains)
	require.Equal(t, federation.Never, got.EmailVerification, "the zero verification mode is the safest")

	single := spec(t, "tenant-a", "single")
	single.Tenant = principal.TenantID{}
	h.put(t, single)
	require.Equal(t, withoutStamp(single), withoutStamp(h.get(t, principal.TenantID{}, "single")), "the single tenant is a tenant")

	_, err := h.s.GetProvider(ctx, want.Tenant, "missing")
	require.ErrorIs(t, err, store.ErrNotFound)

	want.Scopes[0] = "mutated"
	want.Domains[0] = "mutated"
	again := h.get(t, want.Tenant, "corp")
	require.Equal(t, "openid", again.Scopes[0], "the store keeps its own copy of the slices")
	again.SealedSecret[0] ^= 0xff
	require.Equal(t, []byte("sealed-tenant-a-corp"), h.get(t, want.Tenant, "corp").SealedSecret)
}

func putRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	legacy := spec(t, "tenant-a", "old")
	legacy.AADVersion = federation.AADVersionLegacy
	require.ErrorIs(t, h.s.PutProvider(ctx, legacy), federation.ErrLegacyAADVersion, "v0.16 secrets are never written fresh (C-58)")
	future := spec(t, "tenant-a", "future")
	future.AADVersion = 9
	require.ErrorIs(t, h.s.PutProvider(ctx, future), federation.ErrLegacyAADVersion)

	bad := map[string]func(*federation.ProviderSpec){
		"no name":         func(p *federation.ProviderSpec) { p.Name = "" },
		"no secret":       func(p *federation.ProviderSpec) { p.SealedSecret = nil },
		"bad verifcation": func(p *federation.ProviderSpec) { p.EmailVerification = 77 },
		"scope with space": func(p *federation.ProviderSpec) {
			p.Scopes = []string{"openid email"}
		},
		"empty scope": func(p *federation.ProviderSpec) { p.Scopes = []string{""} },
	}
	for name, mutate := range bad {
		p := spec(t, "tenant-a", "bad")
		mutate(&p)
		err := h.s.PutProvider(ctx, p)
		require.Error(t, err, name)
		require.NotErrorIs(t, err, federation.ErrLegacyAADVersion, name)
	}
	list, err := h.s.ListProviders(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, list, "a refused write stores nothing")
	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, h.s.PutProvider(cancelled, spec(t, "tenant-a", "x")))
}

func putReplaces(t *testing.T, h *harness) {
	first := spec(t, "tenant-a", "corp")
	h.put(t, first)
	second := spec(t, "tenant-a", "corp")
	second.ClientID = "rotated"
	second.SealedSecret = []byte("another-sealed")
	second.Scopes = nil
	second.Domains = []string{"new.example.com"}
	second.EmailVerification = federation.Always
	second.Issuer = ""
	h.put(t, second)
	got := h.get(t, first.Tenant, "corp")
	require.Equal(t, withoutStamp(second), withoutStamp(got), "PutProvider replaces the whole spec")
	list, err := h.s.ListProviders(context.Background(), first.Tenant)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func providerIsolation(t *testing.T, h *harness) {
	a := spec(t, "tenant-a", "corp")
	b := spec(t, "tenant-b", "corp")
	h.put(t, a)
	h.put(t, b)
	require.Equal(t, withoutStamp(a), withoutStamp(h.get(t, a.Tenant, "corp")))
	require.Equal(t, withoutStamp(b), withoutStamp(h.get(t, b.Tenant, "corp")), "a provider name is scoped to its tenant")
	_, err := h.s.GetProvider(context.Background(), tenant(t, "tenant-c"), "corp")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func listProviders(t *testing.T, h *harness) {
	ctx := context.Background()
	empty, err := h.s.ListProviders(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, empty)
	for _, n := range []string{"zeta", "alpha", "mid"} {
		h.put(t, spec(t, "tenant-a", n))
	}
	h.put(t, spec(t, "tenant-b", "other"))
	list, err := h.s.ListProviders(ctx, tenant(t, "tenant-a"))
	require.NoError(t, err)
	var names []string
	for _, p := range list {
		names = append(names, p.Name)
		require.Equal(t, tenant(t, "tenant-a"), p.Tenant)
	}
	require.Equal(t, []string{"alpha", "mid", "zeta"}, names, "specs of the tenant only, ordered by name")
}

func deleteProvider(t *testing.T, h *harness) {
	ctx := context.Background()
	p := spec(t, "tenant-a", "corp")
	h.put(t, p)
	h.put(t, spec(t, "tenant-b", "corp"))
	require.NoError(t, h.s.DeleteProvider(ctx, p.Tenant, "corp"))
	_, err := h.s.GetProvider(ctx, p.Tenant, "corp")
	require.ErrorIs(t, err, store.ErrNotFound)
	h.get(t, tenant(t, "tenant-b"), "corp")
	require.NoError(t, h.s.DeleteProvider(ctx, p.Tenant, "corp"), "deleting twice is idempotent")
	require.NoError(t, h.s.DeleteProvider(ctx, p.Tenant, "never-existed"))
}

func emailVerification(t *testing.T, h *harness) {
	for _, v := range []federation.EmailVerification{federation.Never, federation.ClaimBased, federation.Always} {
		p := spec(t, "tenant-a", v.String())
		p.EmailVerification = v
		h.put(t, p)
		require.Equal(t, v, h.get(t, p.Tenant, p.Name).EmailVerification)
	}
}

func link(sub principal.Subject, provider, subject, email string, verified bool, at time.Time) federation.LinkedIdentity {
	return federation.LinkedIdentity{
		Subject:               sub,
		Key:                   federation.LinkKey{Provider: provider, ProviderSubject: subject},
		ProviderEmail:         email,
		ProviderEmailVerified: verified,
		LinkedAt:              at,
	}
}

func (h *harness) seed(t *testing.T, l federation.LinkedIdentity) {
	t.Helper()
	h.f.SeedLink(t, h.s, l)
}

func links(t *testing.T, h *harness) {
	ctx := context.Background()
	base := linkBase()
	alice := h.account(t, "tenant-a")
	google := link(alice, "google", "g-1", "alice@example.com", true, base)
	github := link(alice, "github", "gh-1", "", false, base.Add(time.Hour))
	other := link(h.account(t, "tenant-a"), "google", "g-2", "bob@example.com", false, base)
	h.seed(t, google)
	h.seed(t, github)
	h.seed(t, other)

	got, err := h.s.FindLinked(ctx, alice.Tenant, google.Key)
	require.NoError(t, err)
	require.Equal(t, google, got, "provider_email and the verified flag round-trip")
	got, err = h.s.FindLinked(ctx, alice.Tenant, other.Key)
	require.NoError(t, err)
	require.False(t, got.ProviderEmailVerified)
	got, err = h.s.FindLinked(ctx, alice.Tenant, github.Key)
	require.NoError(t, err)
	require.Empty(t, got.ProviderEmail)
	require.False(t, got.ProviderEmailVerified)

	_, err = h.s.FindLinked(ctx, tenant(t, "tenant-b"), google.Key)
	require.ErrorIs(t, err, store.ErrNotFound, "a link is scoped to its tenant")
	_, err = h.s.FindLinked(ctx, alice.Tenant, federation.LinkKey{Provider: "google", ProviderSubject: "nope"})
	require.ErrorIs(t, err, store.ErrNotFound)

	list, err := h.s.LinkedFor(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, []federation.LinkedIdentity{google, github}, list, "the subject's links, oldest first")
	none, err := h.s.LinkedFor(ctx, subjectIn(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, none, "an unknown subject has no links")
	none, err = h.s.LinkedFor(ctx, h.account(t, "tenant-a"))
	require.NoError(t, err)
	require.Empty(t, none, "an account without a provider has no links")
}

func passwordIsNeverALink(t *testing.T, h *harness) {
	ctx := context.Background()
	alice := h.account(t, "tenant-a")
	h.seed(t, link(alice, "google", "g-1", "", false, linkBase()))
	_, err := h.s.FindLinked(ctx, alice.Tenant, federation.LinkKey{Provider: "password", ProviderSubject: alice.User.String()})
	require.ErrorIs(t, err, store.ErrNotFound, "a password credential is never a federated link")
	list, err := h.s.LinkedFor(ctx, alice)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "google", list[0].Key.Provider, "LinkedFor lists federated providers only")
}

func unverifiedEmail(t *testing.T, h *harness) {
	ctx := context.Background()
	alice := h.account(t, "tenant-a")
	l := link(alice, "github", "1", "", true, linkBase())
	h.seed(t, l)
	got, err := h.s.FindLinked(ctx, alice.Tenant, l.Key)
	require.NoError(t, err)
	require.False(t, got.ProviderEmailVerified, "a verified flag without an email verifies nothing (C-05)")
	list, err := h.s.LinkedFor(ctx, alice)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.False(t, list[0].ProviderEmailVerified, "a verified flag without an email verifies nothing (C-05)")
}

func tombstonedAccount(t *testing.T, h *harness) {
	ctx := context.Background()
	base := linkBase()
	gone := h.account(t, "tenant-a")
	kept := h.account(t, "tenant-a")
	h.seed(t, link(gone, "google", "g-gone", "gone@example.com", true, base))
	h.seed(t, link(kept, "google", "g-kept", "kept@example.com", true, base))
	h.f.Tombstone(t, h.s, gone)

	_, err := h.s.FindLinked(ctx, gone.Tenant, federation.LinkKey{Provider: "google", ProviderSubject: "g-gone"})
	require.ErrorIs(t, err, store.ErrNotFound, "a tombstoned account cannot be logged into through its link")
	list, err := h.s.LinkedFor(ctx, gone)
	require.NoError(t, err)
	require.Empty(t, list, "a tombstoned account lists no link")
	_, err = h.s.FindLinked(ctx, kept.Tenant, federation.LinkKey{Provider: "google", ProviderSubject: "g-kept"})
	require.NoError(t, err, "another account keeps its link")
	require.NoError(t, h.s.DeleteForSubject(ctx, gone), "the erasure of a tombstoned account succeeds")
}

func deleteForSubject(t *testing.T, h *harness) {
	ctx := context.Background()
	base := linkBase()
	alice := h.account(t, "tenant-a")
	bob := h.account(t, "tenant-a")
	h.seed(t, link(alice, "google", "g-1", "a@example.com", true, base))
	h.seed(t, link(alice, "github", "gh-1", "", false, base))
	h.seed(t, link(bob, "google", "g-2", "b@example.com", true, base))
	h.put(t, spec(t, "tenant-a", "corp"))

	require.NoError(t, h.s.DeleteForSubject(ctx, alice))
	list, err := h.s.LinkedFor(ctx, alice)
	require.NoError(t, err)
	require.Empty(t, list)
	_, err = h.s.FindLinked(ctx, alice.Tenant, federation.LinkKey{Provider: "google", ProviderSubject: "g-1"})
	require.ErrorIs(t, err, store.ErrNotFound)
	list, err = h.s.LinkedFor(ctx, bob)
	require.NoError(t, err)
	require.Len(t, list, 1, "another subject keeps its links")
	h.get(t, alice.Tenant, "corp")
	require.NoError(t, h.s.DeleteForSubject(ctx, alice), "deleting twice is idempotent")
	require.NoError(t, h.s.DeleteForSubject(ctx, subjectIn(t, "tenant-a")), "an unknown subject has nothing to delete")
}

func eraseTenant(t *testing.T, h *harness) {
	ctx := context.Background()
	base := linkBase()
	a, b := tenant(t, "tenant-a"), tenant(t, "tenant-b")
	h.put(t, spec(t, "tenant-a", "corp"))
	h.put(t, spec(t, "tenant-a", "other"))
	h.put(t, spec(t, "tenant-b", "corp"))
	legacy := spec(t, "tenant-a", "old")
	h.f.SeedV016(t, h.s, legacyOf(legacy, []byte("v016")))
	inA, inB := h.account(t, "tenant-a"), h.account(t, "tenant-b")
	h.seed(t, link(inA, "google", "g-a", "", false, base))
	h.seed(t, link(inB, "google", "g-b", "", false, base))

	require.NoError(t, h.s.EraseTenant(ctx, a))
	list, err := h.s.ListProviders(ctx, a)
	require.NoError(t, err)
	require.Empty(t, list, "every provider of the tenant is gone")
	_, err = h.s.FindLinked(ctx, a, federation.LinkKey{Provider: "google", ProviderSubject: "g-a"})
	require.ErrorIs(t, err, store.ErrNotFound)
	linked, err := h.s.LinkedFor(ctx, inA)
	require.NoError(t, err)
	require.Empty(t, linked, "every link of the tenant is gone")
	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "legacy rows of the tenant are erased too")
	h.get(t, b, "corp")
	_, err = h.s.FindLinked(ctx, b, federation.LinkKey{Provider: "google", ProviderSubject: "g-b"})
	require.NoError(t, err, "another tenant is untouched")
	require.NoError(t, h.s.EraseTenant(ctx, a), "erasing twice is idempotent")
	h.put(t, spec(t, "tenant-a", "corp"))
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
	p := spec(t, "tenant-a", "corp")
	ref, err := sealing.OAuthClientSecret(p.Tenant, p.Name)
	require.NoError(t, err)
	plain := []byte("s3cr3t-client-secret-value")
	p.SealedSecret, err = sealing.Seal(ctx, k, ref, plain)
	require.NoError(t, err)
	h.put(t, p)

	got := h.get(t, p.Tenant, p.Name)
	require.Equal(t, p.SealedSecret, got.SealedSecret, "the store returns exactly the opaque bytes it was given")
	requireSealedBy(t, k, ref, got.SealedSecret)
	require.False(t, bytes.Contains(got.SealedSecret, plain), "the ciphertext is never the plaintext")
	opened, err := sealing.Open(ctx, k, ref, got.SealedSecret)
	require.NoError(t, err)
	require.Equal(t, plain, opened.Plaintext)
	require.False(t, opened.Stale)

	elsewhere, err := sealing.OAuthClientSecret(tenant(t, "tenant-b"), p.Name)
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, elsewhere, got.SealedSecret)
	require.Error(t, err, "another tenant's associated data fails")
	otherProvider, err := sealing.OAuthClientSecret(p.Tenant, "other")
	require.NoError(t, err)
	_, err = sealing.Open(ctx, k, otherProvider, got.SealedSecret)
	require.Error(t, err, "another provider's associated data fails")
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
	key, err := hex.DecodeString(f.Key)
	require.NoError(t, err)
	opener, err := kek.LegacyLocalV016(key)
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

func legacyOf(p federation.ProviderSpec, sealed []byte) federation.ProviderSpec {
	p.SealedSecret = sealed
	p.AADVersion = federation.AADVersionLegacy
	return p
}

type legacyRow struct {
	spec      federation.ProviderSpec
	plaintext []byte
}

func seedLegacy(t *testing.T, h *harness) []legacyRow {
	t.Helper()
	_, cases := loadLegacy(t)
	rows := []legacyRow{
		{spec: legacyOf(spec(t, "tenant-a", "google"), cases["oauth_oidc_providers tenant:provider"][0]), plaintext: cases["oauth_oidc_providers tenant:provider"][1]},
		{spec: legacyOf(spec(t, "tenant-z", "okta"), cases["no aad"][0]), plaintext: cases["no aad"][1]},
		{spec: legacyOf(spec(t, "tenant-a", "broken"), bytes.Repeat([]byte{7}, 64))},
	}
	for _, r := range rows {
		h.f.SeedV016(t, h.s, r.spec)
	}
	return rows
}

func legacyUpgrade(t *testing.T, h *harness) {
	ctx := context.Background()
	legacy, _ := loadLegacy(t)
	rows := seedLegacy(t, h)
	h.put(t, spec(t, "tenant-a", "fresh"))

	n, err := h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, len(rows), n, "only aad_version 0 rows are legacy")

	var listed []federation.V016Row
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

	byRef := map[federation.SealedRef]federation.V016Row{}
	for _, r := range listed {
		byRef[r.Ref] = r
	}
	require.NotContains(t, byRef, federation.SealedRef{Tenant: tenant(t, "tenant-a"), Provider: "fresh"})

	k := freshKEK(t)
	reported := 0
	for _, want := range rows {
		ref := federation.SealedRef{Tenant: want.spec.Tenant, Provider: want.spec.Name}
		got, ok := byRef[ref]
		require.True(t, ok)
		require.Equal(t, want.spec.SealedSecret, got.Sealed)
		sref, err := sealing.OAuthClientSecret(ref.Tenant, ref.Provider)
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
		ok, err = h.s.ReplaceSealed(ctx, federation.Reseal{Ref: ref, Old: got.Sealed, New: ct})
		require.NoError(t, err)
		require.True(t, ok)
		now := h.get(t, ref.Tenant, ref.Provider)
		require.Equal(t, federation.AADVersionCurrent, now.AADVersion)
		requireSealedBy(t, k, sref, now.SealedSecret)
		require.False(t, bytes.Contains(now.SealedSecret, want.plaintext), "the converted ciphertext is never the plaintext")
		opened, err := sealing.Open(ctx, k, sref, now.SealedSecret)
		require.NoError(t, err)
		require.Equal(t, want.plaintext, opened.Plaintext, "the converted secret opens under the v0.17 AAD")
	}
	require.Equal(t, 1, reported)
	n, err = h.s.CountLegacySealed(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "only the unopenable row remains")
}

func replaceSealedCAS(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	ref := federation.SealedRef{Tenant: rows[0].spec.Tenant, Provider: rows[0].spec.Name}
	before := h.get(t, ref.Tenant, ref.Provider)
	require.Equal(t, federation.AADVersionLegacy, before.AADVersion)

	ok, err := h.s.ReplaceSealed(ctx, federation.Reseal{Ref: ref, Old: []byte("stale"), New: []byte("new")})
	require.NoError(t, err)
	require.False(t, ok, "a secret replaced in the meantime is never overwritten")
	require.Equal(t, before, h.get(t, ref.Tenant, ref.Provider))

	ok, err = h.s.ReplaceSealed(ctx, federation.Reseal{
		Ref: federation.SealedRef{Tenant: ref.Tenant, Provider: "unknown"}, Old: before.SealedSecret, New: []byte("new"),
	})
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = h.s.ReplaceSealed(ctx, federation.Reseal{
		Ref: federation.SealedRef{Tenant: tenant(t, "tenant-other"), Provider: ref.Provider}, Old: before.SealedSecret, New: []byte("new"),
	})
	require.NoError(t, err)
	require.False(t, ok, "the reference is scoped to its tenant")

	ok, err = h.s.ReplaceSealed(ctx, federation.Reseal{Ref: ref, Old: before.SealedSecret, New: []byte("resealed")})
	require.NoError(t, err)
	require.True(t, ok)
	after := h.get(t, ref.Tenant, ref.Provider)
	require.Equal(t, []byte("resealed"), after.SealedSecret)
	require.Equal(t, federation.AADVersionCurrent, after.AADVersion)
	before.SealedSecret, before.AADVersion = after.SealedSecret, after.AADVersion
	require.Equal(t, before, after, "ReplaceSealed changes no other field, the update stamp included")

	ok, err = h.s.ReplaceSealed(ctx, federation.Reseal{Ref: ref, Old: []byte("resealed"), New: []byte("rotated")})
	require.NoError(t, err)
	require.True(t, ok, "a lazy re-seal after a KEK rotation replaces a current row too")
	require.Equal(t, federation.AADVersionCurrent, h.get(t, ref.Tenant, ref.Provider).AADVersion)
}

func replaceSealedRace(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	ref := federation.SealedRef{Tenant: rows[0].spec.Tenant, Provider: rows[0].spec.Name}
	old := h.get(t, ref.Tenant, ref.Provider).SealedSecret
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			ok, err := h.s.ReplaceSealed(ctx, federation.Reseal{Ref: ref, Old: old, New: []byte{byte(i), 1, 2, 3}})
			if err == nil && ok {
				wins.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "exactly one concurrent re-seal wins the compare-and-swap")
}

func replaceSealedRefusals(t *testing.T, h *harness) {
	ctx := context.Background()
	rows := seedLegacy(t, h)
	ref := federation.SealedRef{Tenant: rows[0].spec.Tenant, Provider: rows[0].spec.Name}
	old := h.get(t, ref.Tenant, ref.Provider).SealedSecret
	for name, r := range map[string]federation.Reseal{
		"empty new": {Ref: ref, Old: old},
		"empty old": {Ref: ref, New: []byte("x")},
		"no ref":    {Old: old, New: []byte("x")},
	} {
		ok, err := h.s.ReplaceSealed(ctx, r)
		require.Error(t, err, name)
		require.False(t, ok, name)
	}
	require.Equal(t, old, h.get(t, ref.Tenant, ref.Provider).SealedSecret)
}
