package egauth_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	fedstore "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/mfa"
)

type v016Fixtures struct {
	Key   string
	Cases []struct{ Name, AAD, Plaintext, Blob string }
}

type v016Case struct{ blob, plaintext []byte }

func loadV016(t *testing.T) (kek.LegacyOpener, map[string]v016Case) {
	t.Helper()
	raw, err := os.ReadFile("kek/testdata/v016_fixtures.json")
	require.NoError(t, err)
	var f v016Fixtures
	require.NoError(t, json.Unmarshal(raw, &f))
	key, err := hex.DecodeString(f.Key)
	require.NoError(t, err)
	opener, err := kek.LegacyLocalV016(key)
	require.NoError(t, err)
	out := map[string]v016Case{}
	for _, c := range f.Cases {
		blob, err := hex.DecodeString(c.Blob)
		require.NoError(t, err)
		pt, err := hex.DecodeString(c.Plaintext)
		require.NoError(t, err)
		out[c.Name] = v016Case{blob: blob, plaintext: pt}
	}
	return opener, out
}

type ledger struct {
	mu        sync.Mutex
	blobs     [][]byte
	current   []bool
	writes    []int
	failList  error
	beforeCAS func(i int)
}

func newLedger(blobs ...[]byte) *ledger {
	return &ledger{blobs: blobs, current: make([]bool, len(blobs)), writes: make([]int, len(blobs))}
}

func (l *ledger) page(after store.Cursor, limit int) ([]int, [][]byte, store.Cursor, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failList != nil {
		return nil, nil, after, l.failList
	}
	var out []int
	var snap [][]byte
	next := after
	for i := int(after.Position()); i < len(l.blobs) && len(out) < limit; i++ {
		next = store.RestoreCursor(uint64(i + 1))
		if !l.current[i] {
			out = append(out, i)
			snap = append(snap, bytes.Clone(l.blobs[i]))
		}
	}
	return out, snap, next, nil
}

func (l *ledger) cas(i int, old, replacement []byte) bool {
	if l.beforeCAS != nil {
		l.beforeCAS(i)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current[i] || !bytes.Equal(l.blobs[i], old) {
		return false
	}
	l.blobs[i], l.current[i] = replacement, true
	l.writes[i]++
	return true
}

func (l *ledger) blob(i int) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.blobs[i]
}

type fakeMFA struct {
	mfa.Store
	subjects []principal.Subject
	l        *ledger
}

func (f *fakeMFA) V016Sealed(_ context.Context, after store.Cursor, limit int) ([]mfa.V016Row, store.Cursor, error) {
	idx, snap, next, err := f.l.page(after, limit)
	var out []mfa.V016Row
	for n, i := range idx {
		out = append(out, mfa.V016Row{Ref: mfa.SealedRef{Subject: f.subjects[i]}, Sealed: snap[n]})
	}
	return out, next, err
}

func (f *fakeMFA) ReplaceSealed(_ context.Context, r mfa.Reseal) (bool, error) {
	for i, s := range f.subjects {
		if s == r.Ref.Subject {
			return f.l.cas(i, r.Old, r.New), nil
		}
	}
	return false, nil
}

type fakeFederation struct {
	fedstore.Store
	refs []fedstore.SealedRef
	l    *ledger
}

func (f *fakeFederation) V016Sealed(_ context.Context, after store.Cursor, limit int) ([]fedstore.V016Row, store.Cursor, error) {
	idx, snap, next, err := f.l.page(after, limit)
	var out []fedstore.V016Row
	for n, i := range idx {
		out = append(out, fedstore.V016Row{Ref: f.refs[i], Sealed: snap[n]})
	}
	return out, next, err
}

func (f *fakeFederation) ReplaceSealed(_ context.Context, r fedstore.Reseal) (bool, error) {
	for i, ref := range f.refs {
		if ref == r.Ref {
			return f.l.cas(i, r.Old, r.New), nil
		}
	}
	return false, nil
}

type fakeKeys struct {
	keys.Store
	refs []keys.SealedRef
	l    *ledger
}

func (f *fakeKeys) V016Sealed(_ context.Context, after store.Cursor, limit int) ([]keys.V016Row, store.Cursor, error) {
	idx, snap, next, err := f.l.page(after, limit)
	var out []keys.V016Row
	for n, i := range idx {
		out = append(out, keys.V016Row{Ref: f.refs[i], Sealed: snap[n]})
	}
	return out, next, err
}

func (f *fakeKeys) ReplaceSealed(_ context.Context, r keys.Reseal) (bool, error) {
	for i, ref := range f.refs {
		if ref == r.Ref {
			return f.l.cas(i, r.Old, r.New), nil
		}
	}
	return false, nil
}

type upgradeWorld struct {
	st     egauth.Storage
	legacy kek.LegacyOpener
	k      kek.KEK
	cases  map[string]v016Case
	mfa    *fakeMFA
	fed    *fakeFederation
	keys   *fakeKeys
	tenant principal.TenantID
}

const fixtureUser = "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"

func newUpgradeWorld(t *testing.T) *upgradeWorld {
	t.Helper()
	legacy, cases := loadV016(t)
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	st := memstore.New(testKEK(t))
	w := &upgradeWorld{st: st, legacy: legacy, k: testKEK(t), cases: cases, tenant: tn}
	w.mfa = &fakeMFA{Store: st.MFA, l: newLedger(cases["mfa_totp tenant:user"].blob, cases["no aad"].blob),
		subjects: []principal.Subject{{Tenant: tn, User: uuid.MustParse(fixtureUser)}, {User: uuid.New()}}}
	w.fed = &fakeFederation{Store: st.Federation, l: newLedger(cases["oauth_oidc_providers tenant:provider"].blob),
		refs: []fedstore.SealedRef{{Tenant: tn, Provider: "google"}}}
	w.keys = &fakeKeys{Store: st.Keys, l: newLedger(cases["keystore_keys tenant"].blob, cases["no aad"].blob),
		refs: []keys.SealedRef{{Tenant: tn, KeyID: "k1"}, {Tenant: tn, KeyID: "k2"}}}
	w.st.MFA, w.st.Federation, w.st.Keys = w.mfa, w.fed, w.keys
	return w
}

func (w *upgradeWorld) run(t *testing.T) (egauth.UpgradeReport, error) {
	t.Helper()
	return egauth.UpgradeSecretsV016(context.Background(), w.st, w.legacy, w.k)
}

func TestUpgradeSecretsV016ReSealsEveryKindUnderTheNewAAD(t *testing.T) {
	w := newUpgradeWorld(t)
	rep, err := w.run(t)
	require.NoError(t, err)
	require.Equal(t, egauth.UpgradeReport{Upgraded: 5}, rep)
	ctx := context.Background()

	totp, err := sealing.TOTPSecret(w.mfa.subjects[0])
	require.NoError(t, err)
	opened, err := sealing.Open(ctx, w.k, totp, w.mfa.l.blob(0))
	require.NoError(t, err)
	require.Equal(t, w.cases["mfa_totp tenant:user"].plaintext, opened.Plaintext)
	noAAD, err := sealing.TOTPSecret(w.mfa.subjects[1])
	require.NoError(t, err)
	opened, err = sealing.Open(ctx, w.k, noAAD, w.mfa.l.blob(1))
	require.NoError(t, err)
	require.Equal(t, w.cases["no aad"].plaintext, opened.Plaintext, "the no-AAD fallback is tried after the tenant:user form")

	oauth, err := sealing.OAuthClientSecret(w.tenant, "google")
	require.NoError(t, err)
	opened, err = sealing.Open(ctx, w.k, oauth, w.fed.l.blob(0))
	require.NoError(t, err)
	require.Equal(t, w.cases["oauth_oidc_providers tenant:provider"].plaintext, opened.Plaintext)

	for i, kid := range []string{"k1", "k2"} {
		ref, err := sealing.SigningKey(w.tenant, kid)
		require.NoError(t, err)
		opened, err = sealing.Open(ctx, w.k, ref, w.keys.l.blob(i))
		require.NoError(t, err)
		want := w.cases["keystore_keys tenant"].plaintext
		if i == 1 {
			want = w.cases["no aad"].plaintext
		}
		require.Equal(t, want, opened.Plaintext)
	}
	moved, err := sealing.TOTPSecret(principal.Subject{Tenant: w.tenant, User: uuid.New()})
	require.NoError(t, err)
	_, err = sealing.Open(ctx, w.k, moved, w.mfa.l.blob(0))
	require.Error(t, err, "the new AAD binds the row")
}

func TestUpgradeSecretsV016IsIdempotent(t *testing.T) {
	w := newUpgradeWorld(t)
	_, err := w.run(t)
	require.NoError(t, err)
	before := bytes.Clone(w.mfa.l.blob(0))
	rep, err := w.run(t)
	require.NoError(t, err)
	require.Equal(t, egauth.UpgradeReport{}, rep)
	require.Equal(t, before, w.mfa.l.blob(0))
}

func TestUpgradeSecretsV016ReportsARowNoCandidateOpens(t *testing.T) {
	w := newUpgradeWorld(t)
	w.mfa.l.blobs[1] = bytes.Repeat([]byte{7}, 64)
	rep, err := w.run(t)
	require.ErrorIs(t, err, egauth.ErrUpgradeIncomplete)
	require.Equal(t, 4, rep.Upgraded, "every other row is still upgraded")
	require.Equal(t, []egauth.UpgradeRow{{Kind: "mfa_totp", ID: w.mfa.subjects[1].User.String()}}, rep.Unopenable)
	require.False(t, w.mfa.l.current[1], "the unopenable row stays untouched")
	require.Equal(t, bytes.Repeat([]byte{7}, 64), w.mfa.l.blob(1))
}

func TestUpgradeSecretsV016NeverOverwritesARowChangedMeanwhile(t *testing.T) {
	w := newUpgradeWorld(t)
	replacement := []byte("replaced by another instance")
	w.fed.l.beforeCAS = func(i int) {
		w.fed.l.mu.Lock()
		w.fed.l.blobs[i] = replacement
		w.fed.l.mu.Unlock()
	}
	rep, err := w.run(t)
	require.NoError(t, err)
	require.Equal(t, egauth.UpgradeReport{Upgraded: 4, Concurrent: 1}, rep)
	require.Equal(t, replacement, w.fed.l.blob(0))
	require.False(t, w.fed.l.current[0])
}

func TestUpgradeSecretsV016IsSafeAcrossConcurrentInstances(t *testing.T) {
	const rows = 250
	legacy, cases := loadV016(t)
	st := memstore.New(testKEK(t))
	blobs := make([][]byte, rows)
	subjects := make([]principal.Subject, rows)
	for i := range blobs {
		blobs[i], subjects[i] = cases["no aad"].blob, principal.Subject{User: uuid.New()}
	}
	f := &fakeMFA{Store: st.MFA, l: newLedger(blobs...), subjects: subjects}
	st.MFA = f
	const instances = 4
	reports := make([]egauth.UpgradeReport, instances)
	errs := make([]error, instances)
	var wg sync.WaitGroup
	for i := range instances {
		wg.Go(func() {
			reports[i], errs[i] = egauth.UpgradeSecretsV016(context.Background(), st, legacy, testKEK(t))
		})
	}
	wg.Wait()
	total := 0
	for i := range instances {
		require.NoError(t, errs[i])
		total += reports[i].Upgraded
	}
	require.Equal(t, rows, total, "each row is re-sealed by exactly one instance")
	for i, n := range f.l.writes {
		require.Equal(t, 1, n, "row %d", i)
	}
}

func TestUpgradeSecretsV016StopsOnAStoreFailure(t *testing.T) {
	w := newUpgradeWorld(t)
	boom := errors.New("store down")
	w.fed.l.failList = boom
	_, err := w.run(t)
	require.ErrorIs(t, err, boom)
}

func TestUpgradeSecretsV016SkipsStoresAbsentFromStorage(t *testing.T) {
	w := newUpgradeWorld(t)
	w.st.Federation, w.st.Keys = nil, nil
	rep, err := w.run(t)
	require.NoError(t, err)
	require.Equal(t, 2, rep.Upgraded)
}

func TestUpgradeSecretsV016NeedsItsDependencies(t *testing.T) {
	w := newUpgradeWorld(t)
	ctx := context.Background()
	_, err := egauth.UpgradeSecretsV016(ctx, w.st, w.legacy, nil)
	require.Error(t, err)
	_, err = egauth.UpgradeSecretsV016(ctx, w.st, nil, w.k)
	require.Error(t, err)
	_, err = egauth.UpgradeSecretsV016(ctx, egauth.Storage{}, w.legacy, w.k)
	require.Error(t, err)
}

type outageOpener struct{ err error }

func (o outageOpener) OpenLegacy(context.Context, []byte, kek.AAD) ([]byte, error) { return nil, o.err }

func TestUpgradeSecretsV016StopsOnALegacyOpenerOutage(t *testing.T) {
	w := newUpgradeWorld(t)
	boom := errors.New("remote kms unreachable")
	rep, err := egauth.UpgradeSecretsV016(context.Background(), w.st, outageOpener{err: boom}, w.k)
	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, egauth.ErrUpgradeIncomplete)
	require.Empty(t, rep.Unopenable, "an outage never turns rows into unopenable ones")
	require.False(t, w.mfa.l.current[0])
}

func TestUpgradeSecretsV016StopsOnACancelledContext(t *testing.T) {
	w := newUpgradeWorld(t)
	w.mfa.l.blobs[0] = bytes.Repeat([]byte{7}, 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := egauth.UpgradeSecretsV016(ctx, w.st, w.legacy, w.k)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, rep.Unopenable)
}
