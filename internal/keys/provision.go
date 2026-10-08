package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	storekeys "github.com/JLugagne/egauth/store/keys"
)

const (
	generatedRSABits = 3072
	hs256KeyBytes    = 32
	keyIDBytes       = 16
)

// RenewRequest installs a freshly generated key as Tenant's signer. Alg defaults to
// DefaultAlgorithm. Lifetime bounds the new key (DefaultExpiry is DefaultLifetime). Overlap is how
// long the previous signer keeps verifying (DefaultExpiry is DefaultOverlap); it must be bounded and
// at most MaxOverlap. Both are required even when Tenant has no key yet: the zero Expiry is
// invalid (X-16).
type RenewRequest struct {
	Tenant   principal.TenantID
	Alg      string
	Lifetime storekeys.Expiry
	Overlap  storekeys.Expiry
}

// ImportRequest installs caller-supplied key material as Tenant's signer, under the rules of
// RenewRequest. Material is what the signing constructor of Alg accepts (a PKCS#8 private key, an
// Ed25519 seed or raw P-256 scalar, or an HS256 secret of at least 32 bytes); it is validated,
// sealed and never kept, and the caller's slice is left untouched.
type ImportRequest struct {
	Tenant   principal.TenantID
	KeyID    string
	Alg      string
	Material []byte
	Lifetime storekeys.Expiry
	Overlap  storekeys.Expiry
}

// String renders r with Material redacted.
func (r ImportRequest) String() string {
	return "keys.ImportRequest{Tenant: " + r.Tenant.String() + ", KeyID: " + r.KeyID + ", Alg: " + r.Alg + ", Material: REDACTED}"
}

// GoString renders like String.
func (r ImportRequest) GoString() string { return r.String() }

// LogValue renders r with Material redacted.
func (r ImportRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant", r.Tenant.String()),
		slog.String("kid", r.KeyID),
		slog.String("alg", r.Alg),
		slog.String("material", "REDACTED"),
	)
}

// Renew generates a key and installs it as req.Tenant's signer: the tenant's first key, or a
// rotation that retires the current signer after req.Overlap. It returns ErrStaticKeys for static
// keys, ErrUnsupportedAlgorithm, storekeys.ErrInvalidExpiry for a zero Expiry or a key already
// expired at creation, storekeys.ErrUnboundedOverlap or ErrOverlapTooLong for the overlap,
// storekeys.ErrTenantTombstoned for an erased tenant, and store.ErrConflict when a concurrent
// rotation won. This instance's cache is refreshed at once; other instances follow within
// revoke.PollBound.
func (m *Manager) Renew(ctx context.Context, req RenewRequest) error {
	if m.static != nil {
		return ErrStaticKeys
	}
	alg := req.Alg
	if alg == "" {
		alg = DefaultAlgorithm
	}
	plan, err := m.tenant.plan(req.Lifetime, req.Overlap)
	if err != nil {
		return err
	}
	if err := checkAlgorithm(alg); err != nil {
		return err
	}
	if err := m.tenant.refuseTombstoned(ctx, req.Tenant); err != nil {
		return err
	}
	kid, err := newKeyID()
	if err != nil {
		return err
	}
	material, err := generate(alg)
	if err != nil {
		return err
	}
	defer clear(material)
	if _, err := newSigner(alg, kid, material); err != nil {
		return err
	}
	return m.tenant.install(ctx, req.Tenant, kid, alg, material, plan)
}

// Import validates req.Material and installs it as req.Tenant's signer, like Renew. It also
// returns signing.ErrInvalidKey or signing.ErrInvalidKeyID for material or a key id the signing
// package refuses, and store.ErrConflict when the key id exists in the tenant.
func (m *Manager) Import(ctx context.Context, req ImportRequest) error {
	if m.static != nil {
		return ErrStaticKeys
	}
	plan, err := m.tenant.plan(req.Lifetime, req.Overlap)
	if err != nil {
		return err
	}
	if err := checkAlgorithm(req.Alg); err != nil {
		return err
	}
	if _, err := newSigner(req.Alg, req.KeyID, req.Material); err != nil {
		return err
	}
	if err := m.tenant.refuseTombstoned(ctx, req.Tenant); err != nil {
		return err
	}
	return m.tenant.install(ctx, req.Tenant, req.KeyID, req.Alg, req.Material, plan)
}

// RevokeAll deletes every key of t at once, for a key compromise: tokens they signed stop
// verifying here at once and on other instances within revoke.PollBound. It returns ErrStaticKeys
// for static keys.
func (m *Manager) RevokeAll(ctx context.Context, t principal.TenantID) error {
	if m.static != nil {
		return ErrStaticKeys
	}
	defer m.tenant.cache.Forget(t)
	return m.tenant.store.RevokeTenantKeys(ctx, t)
}

// Tombstone erases t's keys and forbids provisioning t again (T-13). It is idempotent, and a no-op
// for static keys, which belong to no tenant.
func (m *Manager) Tombstone(ctx context.Context, t principal.TenantID) error {
	if m.static != nil {
		return nil
	}
	defer m.tenant.cache.Forget(t)
	return m.tenant.store.Tombstone(ctx, t)
}

type plan struct {
	now      time.Time
	notAfter time.Time
	overlap  time.Time
}

func (t *tenantKeys) plan(lifetime, overlap storekeys.Expiry) (plan, error) {
	now := t.clk.Now().UTC().Truncate(time.Microsecond)
	notAfter, err := lifetime.At(now, DefaultLifetime)
	if err != nil {
		return plan{}, err
	}
	if !notAfter.IsZero() && !notAfter.After(now) {
		return plan{}, errors.Join(storekeys.ErrInvalidExpiry, errors.New("keys: key lifetime must be positive"))
	}
	until, err := overlap.OverlapUntil(now, DefaultOverlap)
	if err != nil {
		return plan{}, err
	}
	if until.Sub(now) > MaxOverlap {
		return plan{}, ErrOverlapTooLong
	}
	return plan{now: now, notAfter: notAfter, overlap: until}, nil
}

func (t *tenantKeys) refuseTombstoned(ctx context.Context, tn principal.TenantID) error {
	dead, err := t.store.IsTombstoned(ctx, tn)
	if err != nil {
		return err
	}
	if dead {
		return storekeys.ErrTenantTombstoned
	}
	return nil
}

func (t *tenantKeys) install(ctx context.Context, tn principal.TenantID, kid, alg string, material []byte, p plan) error {
	ref, err := sealing.SigningKey(tn, kid)
	if err != nil {
		return err
	}
	sealed, err := sealing.Seal(ctx, t.kek, ref, material)
	if err != nil {
		return err
	}
	k := storekeys.Key{
		Tenant:     tn,
		KeyID:      kid,
		Alg:        alg,
		Sealed:     sealed,
		AADVersion: storekeys.AADVersionCurrent,
		CreatedAt:  p.now,
		NotAfter:   p.notAfter,
	}
	defer t.cache.Forget(tn)
	active, err := t.store.ActiveKey(ctx, tn)
	switch {
	case err == nil:
		return t.store.Rotate(ctx, storekeys.Rotation{Previous: active.KeyID, Next: k, RetiredAt: p.now, OverlapUntil: p.overlap})
	case !errors.Is(err, storekeys.ErrNoActiveKey):
		return err
	}
	exists, err := t.store.TenantExists(ctx, tn)
	if err != nil {
		return err
	}
	if exists {
		return t.store.PutKey(ctx, k)
	}
	return t.store.CreateTenant(ctx, k)
}

func checkAlgorithm(alg string) error {
	switch alg {
	case signing.AlgEdDSA, signing.AlgES256, signing.AlgRS256, signing.AlgHS256:
		return nil
	}
	return errors.Join(ErrUnsupportedAlgorithm, errors.New("keys: algorithm "+alg))
}

func newKeyID() (string, error) {
	b := make([]byte, keyIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Join(errors.New("keys: generate key id"), err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generate(alg string) ([]byte, error) {
	switch alg {
	case signing.AlgHS256:
		b := make([]byte, hs256KeyBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, errors.Join(errors.New("keys: generate HS256 key"), err)
		}
		return b, nil
	case signing.AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Join(errors.New("keys: generate EdDSA key"), err)
		}
		return pkcs8(priv)
	case signing.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.Join(errors.New("keys: generate ES256 key"), err)
		}
		return pkcs8(priv)
	case signing.AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, generatedRSABits)
		if err != nil {
			return nil, errors.Join(errors.New("keys: generate RS256 key"), err)
		}
		return pkcs8(priv)
	}
	return nil, errors.Join(ErrUnsupportedAlgorithm, errors.New("keys: algorithm "+alg))
}

func pkcs8(priv any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.Join(errors.New("keys: encode private key"), err)
	}
	return der, nil
}
