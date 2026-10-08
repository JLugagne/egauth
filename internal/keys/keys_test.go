package keys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	storekeys "github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/keys/memory"
)

var start = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func tenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID(s)
	require.NoError(t, err)
	return id
}

func localKEK(t *testing.T, current []byte, previous ...[]byte) *kek.Local {
	t.Helper()
	k, err := kek.NewLocal(current, previous...)
	require.NoError(t, err)
	return k
}

func expireAfter(t *testing.T, d time.Duration) storekeys.Expiry {
	t.Helper()
	e, err := storekeys.ExpireAfter(d)
	require.NoError(t, err)
	return e
}

type env struct {
	clk   *clock.Test
	store *memory.Store
	kek   kek.KEK
	m     *keys.Manager
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := clock.NewTest(start)
	st := memory.NewWithClock(clk.Clock())
	k := localKEK(t, random(t, kek.KeyLength))
	return &env{clk: clk, store: st, kek: k, m: newTenantManager(t, st, k, clk)}
}

func newTenantManager(t *testing.T, st storekeys.Store, k kek.KEK, clk *clock.Test) *keys.Manager {
	t.Helper()
	m, err := keys.NewTenant(keys.TenantConfig{Store: st, KEK: k, Clock: clk.Clock()})
	require.NoError(t, err)
	t.Cleanup(m.Stop)
	return m
}

func (e *env) renew(t *testing.T, tn principal.TenantID, alg string) signing.Signer {
	t.Helper()
	e.clk.Advance(time.Second)
	require.NoError(t, e.m.Renew(context.Background(), keys.RenewRequest{
		Tenant: tn, Alg: alg, Lifetime: storekeys.DefaultExpiry(), Overlap: expireAfter(t, time.Hour),
	}))
	s, err := e.m.Signer(context.Background(), tn)
	require.NoError(t, err)
	return s
}

func signEd(priv ed25519.PrivateKey, kid, input string) signing.Signed {
	return signing.Signed{Algorithm: signing.AlgEdDSA, KeyID: kid, Input: input, Signature: ed25519.Sign(priv, []byte(input))}
}

func TestStaticKeys(t *testing.T) {
	ctx := context.Background()
	active, err := signing.EdDSA("active", random(t, ed25519.SeedSize))
	require.NoError(t, err)
	old, err := signing.EdDSA("old", random(t, ed25519.SeedSize))
	require.NoError(t, err)
	mac, err := signing.HS256("mac", random(t, 32))
	require.NoError(t, err)
	m, err := keys.NewStatic(active, old.Verifier(), mac.Verifier())
	require.NoError(t, err)

	for _, tn := range []principal.TenantID{{}, tenant(t, "acme")} {
		s, err := m.Signer(ctx, tn)
		require.NoError(t, err)
		require.Equal(t, "active", s.KeyID())
		v, err := m.Verifier(ctx, tn, "old")
		require.NoError(t, err)
		require.Equal(t, "old", v.KeyID())
	}
	_, err = m.Verifier(ctx, principal.TenantID{}, "unknown")
	require.ErrorIs(t, err, keys.ErrUnknownKey)

	pub, err := m.Published(ctx, principal.TenantID{})
	require.NoError(t, err)
	var kids []string
	for _, v := range pub {
		kids = append(kids, v.KeyID())
	}
	require.ElementsMatch(t, []string{"active", "old"}, kids, "HS256 keys are never published")

	acme := tenant(t, "acme")
	require.ErrorIs(t, m.Renew(ctx, keys.RenewRequest{Tenant: acme, Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry()}), keys.ErrStaticKeys)
	require.ErrorIs(t, m.Import(ctx, keys.ImportRequest{Tenant: acme}), keys.ErrStaticKeys)
	require.ErrorIs(t, m.RevokeAll(ctx, acme), keys.ErrStaticKeys)
	require.NoError(t, m.Tombstone(ctx, acme), "erasing a tenant under static keys has no key to erase")
	require.NoError(t, m.Ready())
	m.Start()
	m.Stop()
}

func TestStaticKeysValidation(t *testing.T) {
	a, err := signing.EdDSA("a", random(t, ed25519.SeedSize))
	require.NoError(t, err)
	_, err = keys.NewStatic(signing.Signer{})
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
	_, err = keys.NewStatic(a, signing.Verifier{})
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
	_, err = keys.NewStatic(a, a.Verifier())
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
}

func TestTenantConfigValidation(t *testing.T) {
	k := localKEK(t, random(t, kek.KeyLength))
	_, err := keys.NewTenant(keys.TenantConfig{KEK: k})
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
	_, err = keys.NewTenant(keys.TenantConfig{Store: memory.New()})
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
	_, err = keys.NewTenant(keys.TenantConfig{Store: memory.New(), KEK: k, Capacity: -1})
	require.ErrorIs(t, err, keys.ErrInvalidConfig)
}

func TestImportSignVerify(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	seed := random(t, ed25519.SeedSize)
	material := bytes.Clone(seed)
	require.NoError(t, e.m.Import(ctx, keys.ImportRequest{
		Tenant: acme, KeyID: "imported-1", Alg: signing.AlgEdDSA, Material: material,
		Lifetime: storekeys.NeverExpire(), Overlap: storekeys.DefaultExpiry(),
	}))
	require.Equal(t, seed, material, "the caller's material is left untouched")

	s, err := e.m.Signer(ctx, acme)
	require.NoError(t, err)
	require.Equal(t, "imported-1", s.KeyID())
	v, err := e.m.Verifier(ctx, acme, "imported-1")
	require.NoError(t, err)
	signed := signEd(ed25519.NewKeyFromSeed(seed), "imported-1", "header.payload")
	require.NoError(t, v.Verify(signed))
	signed.Input = "header.tampered"
	require.ErrorIs(t, v.Verify(signed), signing.ErrInvalidSignature)

	_, err = e.m.Verifier(ctx, tenant(t, "other"), "imported-1")
	require.ErrorIs(t, err, keys.ErrUnknownKey, "a key never verifies for another tenant")

	stored, err := e.store.ActiveKey(ctx, acme)
	require.NoError(t, err)
	require.Equal(t, storekeys.AADVersionCurrent, stored.AADVersion)
	require.Equal(t, signing.AlgEdDSA, stored.Alg)
	require.False(t, bytes.Contains(stored.Sealed, seed), "the store only ever sees sealed material")
}

func TestImportHS256SignVerify(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	key := random(t, 32)
	require.NoError(t, e.m.Import(ctx, keys.ImportRequest{
		Tenant: acme, KeyID: "mac-1", Alg: signing.AlgHS256, Material: key,
		Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry(),
	}))
	derived, err := hkdf.Key(sha256.New, key, nil, "egauth/jwt-hs256/v2", 32)
	require.NoError(t, err)
	h := hmac.New(sha256.New, derived)
	h.Write([]byte("header.payload"))
	v, err := e.m.Verifier(ctx, acme, "mac-1")
	require.NoError(t, err)
	require.NoError(t, v.Verify(signing.Signed{Algorithm: signing.AlgHS256, KeyID: "mac-1", Input: "header.payload", Signature: h.Sum(nil)}))
	pub, err := e.m.Published(ctx, acme)
	require.NoError(t, err)
	require.Empty(t, pub)
}

func TestImportRefusesBadMaterial(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	base := keys.ImportRequest{Tenant: acme, KeyID: "k", Alg: signing.AlgHS256, Material: random(t, 32), Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry()}

	short := base
	short.Material = random(t, 16)
	require.ErrorIs(t, e.m.Import(ctx, short), signing.ErrInvalidKey)
	badID := base
	badID.KeyID = "has space"
	require.ErrorIs(t, e.m.Import(ctx, badID), signing.ErrInvalidKeyID)
	badAlg := base
	badAlg.Alg = "none"
	require.ErrorIs(t, e.m.Import(ctx, badAlg), keys.ErrUnsupportedAlgorithm)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	require.NoError(t, err)
	wrongAlg := base
	wrongAlg.Alg = signing.AlgES256
	wrongAlg.Material = edDER
	require.ErrorIs(t, e.m.Import(ctx, wrongAlg), signing.ErrInvalidKey)
	zero := base
	zero.Lifetime = storekeys.Expiry{}
	require.ErrorIs(t, e.m.Import(ctx, zero), storekeys.ErrInvalidExpiry)

	ok, err := e.store.TenantExists(ctx, acme)
	require.NoError(t, err)
	require.False(t, ok, "nothing was written")
}

func TestRenewEveryAlgorithm(t *testing.T) {
	e := newEnv(t)
	for _, alg := range []string{"", signing.AlgEdDSA, signing.AlgES256, signing.AlgRS256, signing.AlgHS256} {
		tn := tenant(t, "t-"+strings.ToLower(alg)+"x")
		s := e.renew(t, tn, alg)
		want := alg
		if want == "" {
			want = keys.DefaultAlgorithm
		}
		require.Equal(t, want, s.Algorithm())
		v, err := e.m.Verifier(context.Background(), tn, s.KeyID())
		require.NoError(t, err)
		require.Equal(t, s.Verifier().Algorithm(), v.Algorithm())
		stored, err := e.store.ActiveKey(context.Background(), tn)
		require.NoError(t, err)
		require.Equal(t, want, stored.Alg)
		require.NotEmpty(t, stored.Sealed)
		require.Equal(t, e.clk.Now().Add(keys.DefaultLifetime), stored.NotAfter)
	}
}

func TestRotationOverlap(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	first := e.renew(t, acme, signing.AlgEdDSA)
	second := e.renew(t, acme, signing.AlgEdDSA)
	require.NotEqual(t, first.KeyID(), second.KeyID())

	s, err := e.m.Signer(ctx, acme)
	require.NoError(t, err)
	require.Equal(t, second.KeyID(), s.KeyID(), "the new key signs at once")
	_, err = e.m.Verifier(ctx, acme, first.KeyID())
	require.NoError(t, err, "the retired key verifies during the overlap")

	e.clk.Advance(time.Hour)
	_, err = e.m.Verifier(ctx, acme, first.KeyID())
	require.ErrorIs(t, err, keys.ErrUnknownKey, "the overlap end is checked at use, even on a cached keyset")
	_, err = e.m.Verifier(ctx, acme, second.KeyID())
	require.NoError(t, err)
}

func TestOverlapIsBounded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	e.renew(t, acme, signing.AlgEdDSA)
	req := keys.RenewRequest{Tenant: acme, Lifetime: storekeys.DefaultExpiry()}

	req.Overlap = storekeys.NeverExpire()
	require.ErrorIs(t, e.m.Renew(ctx, req), storekeys.ErrUnboundedOverlap)
	req.Overlap = expireAfter(t, keys.MaxOverlap+time.Second)
	require.ErrorIs(t, e.m.Renew(ctx, req), keys.ErrOverlapTooLong)
	req.Overlap = storekeys.Expiry{}
	require.ErrorIs(t, e.m.Renew(ctx, req), storekeys.ErrInvalidExpiry)
	req.Overlap = storekeys.DefaultExpiry()
	req.Lifetime = expireAfter(t, 0)
	require.ErrorIs(t, e.m.Renew(ctx, req), storekeys.ErrInvalidExpiry, "a key already expired at creation")
	req.Lifetime = storekeys.Expiry{}
	require.ErrorIs(t, e.m.Renew(ctx, req), storekeys.ErrInvalidExpiry)
	req.Lifetime = storekeys.DefaultExpiry()
	req.Alg = "none"
	require.ErrorIs(t, e.m.Renew(ctx, req), keys.ErrUnsupportedAlgorithm)

	req.Alg = ""
	req.Overlap = expireAfter(t, keys.MaxOverlap)
	e.clk.Advance(time.Second)
	require.NoError(t, e.m.Renew(ctx, req))
}

func TestTombstoneIsHonoured(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	s := e.renew(t, acme, signing.AlgEdDSA)
	require.NoError(t, e.m.Tombstone(ctx, acme))

	_, err := e.m.Signer(ctx, acme)
	require.ErrorIs(t, err, storekeys.ErrNoActiveKey)
	_, err = e.m.Verifier(ctx, acme, s.KeyID())
	require.ErrorIs(t, err, keys.ErrUnknownKey)

	err = e.m.Renew(ctx, keys.RenewRequest{Tenant: acme, Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry()})
	require.ErrorIs(t, err, storekeys.ErrTenantTombstoned, "a tombstone blocks provisioning")
	err = e.m.Import(ctx, keys.ImportRequest{Tenant: acme, KeyID: "k", Alg: signing.AlgHS256, Material: random(t, 32), Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry()})
	require.ErrorIs(t, err, storekeys.ErrTenantTombstoned)
}

func TestRevokeAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	s := e.renew(t, acme, signing.AlgEdDSA)
	require.NoError(t, e.m.RevokeAll(ctx, acme))
	_, err := e.m.Verifier(ctx, acme, s.KeyID())
	require.ErrorIs(t, err, keys.ErrUnknownKey, "this instance forgets its keyset at once")
	n := e.renew(t, acme, signing.AlgEdDSA)
	require.NotEqual(t, s.KeyID(), n.KeyID(), "a revoked tenant can be provisioned again")
}

func TestOtherInstancesFollowKeyChanges(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	s := e.renew(t, acme, signing.AlgEdDSA)
	other := newTenantManager(t, e.store, e.kek, e.clk)
	require.NoError(t, other.Poll(ctx))
	_, err := other.Verifier(ctx, acme, s.KeyID())
	require.NoError(t, err)

	require.NoError(t, e.m.RevokeAll(ctx, acme))
	require.NoError(t, other.Poll(ctx))
	_, err = other.Verifier(ctx, acme, s.KeyID())
	require.ErrorIs(t, err, keys.ErrUnknownKey, "a revocation on one instance reaches the others through ChangesSince, with no wiring (T-15)")

	n := e.renew(t, acme, signing.AlgEdDSA)
	require.NoError(t, other.Poll(ctx))
	got, err := other.Signer(ctx, acme)
	require.NoError(t, err)
	require.Equal(t, n.KeyID(), got.KeyID())
}

func TestDeadPollerStillDropsRevokedKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	s := e.renew(t, acme, signing.AlgEdDSA)
	other := newTenantManager(t, e.store, e.kek, e.clk)
	other.Start()
	require.Eventually(t, func() bool { return other.Ready() == nil }, 5*time.Second, time.Millisecond)
	_, err := other.Verifier(ctx, acme, s.KeyID())
	require.NoError(t, err)
	other.Stop()

	require.NoError(t, e.m.RevokeAll(ctx, acme))
	e.clk.Advance(revoke.PollBound)
	require.ErrorIs(t, other.Ready(), revoke.ErrStale)
	_, err = other.Verifier(ctx, acme, s.KeyID())
	require.ErrorIs(t, err, keys.ErrUnknownKey)
}

type failingStore struct {
	storekeys.Store
	fail atomic.Bool
}

var errDown = errors.New("store down")

func (f *failingStore) VerificationKeys(ctx context.Context, t principal.TenantID) ([]storekeys.Key, error) {
	if f.fail.Load() {
		return nil, errDown
	}
	return f.Store.VerificationKeys(ctx, t)
}

func TestUnavailableStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewTest(start)
	st := &failingStore{Store: memory.NewWithClock(clk.Clock())}
	var events atomic.Int64
	sink := event.SinkFunc(func(_ context.Context, ev event.Event) {
		if ev.Type == event.RevocationUnavailable {
			events.Add(1)
		}
	})
	m, err := keys.NewTenant(keys.TenantConfig{Store: st, KEK: localKEK(t, random(t, kek.KeyLength)), Clock: clk.Clock(), Events: sink})
	require.NoError(t, err)
	st.fail.Store(true)
	_, err = m.Signer(ctx, tenant(t, "acme"))
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	_, err = m.Verifier(ctx, tenant(t, "acme"), "kid")
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	require.Equal(t, int64(2), events.Load())
}

func TestWrongKEKFailsClosed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	e.renew(t, acme, signing.AlgEdDSA)
	stranger := newTenantManager(t, e.store, localKEK(t, random(t, kek.KeyLength)), e.clk)
	_, err := stranger.Signer(ctx, acme)
	require.ErrorIs(t, err, revoke.ErrUnavailable)
}

func TestStaleKEKKeyIsResealed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	acme := tenant(t, "acme")
	oldKey := random(t, kek.KeyLength)
	old := localKEK(t, oldKey)
	m := newTenantManager(t, e.store, old, e.clk)
	e.clk.Advance(time.Second)
	require.NoError(t, m.Renew(ctx, keys.RenewRequest{Tenant: acme, Lifetime: storekeys.DefaultExpiry(), Overlap: storekeys.DefaultExpiry()}))

	rotated := localKEK(t, random(t, kek.KeyLength), oldKey)
	fresh := newTenantManager(t, e.store, rotated, e.clk)
	s, err := fresh.Signer(ctx, acme)
	require.NoError(t, err)
	stored, err := e.store.ActiveKey(ctx, acme)
	require.NoError(t, err)
	id, err := rotated.KeyIDOf(stored.Sealed)
	require.NoError(t, err)
	require.Equal(t, rotated.CurrentKeyID(), id, "material sealed by a previous KEK is re-sealed on load")
	require.Equal(t, s.KeyID(), stored.KeyID)
}

func TestRedaction(t *testing.T) {
	material := []byte("super-secret-material-0123456789")
	req := keys.ImportRequest{Tenant: tenant(t, "acme"), KeyID: "k", Alg: signing.AlgHS256, Material: material}
	for _, out := range []string{fmt.Sprint(req), fmt.Sprintf("%+v", req), fmt.Sprintf("%#v", req)} {
		require.NotContains(t, out, string(material))
		require.Contains(t, out, "REDACTED")
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "req", req)
	require.NotContains(t, buf.String(), string(material))

	e := newEnv(t)
	for _, out := range []string{fmt.Sprint(e.m), fmt.Sprintf("%+v", e.m), fmt.Sprintf("%#v", e.m)} {
		require.NotContains(t, out, "privateKey")
	}

	kekKey := random(t, kek.KeyLength)
	cfg := keys.TenantConfig{Store: e.store, KEK: leakyKEK{KEK: localKEK(t, kekKey), raw: kekKey}}
	buf.Reset()
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "cfg", cfg)
	for _, out := range []string{fmt.Sprint(cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), buf.String()} {
		require.NotContains(t, out, "LEAKED")
		require.Contains(t, out, "REDACTED")
	}
}

type leakyKEK struct {
	kek.KEK
	raw []byte
}

func (l leakyKEK) String() string { return "LEAKED" }
