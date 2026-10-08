// Package keys is the key manager behind the sealed StaticKeys | TenantKeys choice. It hands the
// access-token codec the signer of a tenant and the verifier of a key id, provisions, imports,
// rotates and revokes tenant keys, and honours tenant tombstones. Tenant keysets are cached in the
// one revoke.Keys instance each Manager owns, which follows the keys store's ChangesSince feed, so a
// rotation or revocation on any instance reaches every other one without external wiring (T-15).
// There is no other key cache.
package keys

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	storekeys "github.com/JLugagne/egauth/store/keys"
)

const (
	// DefaultAlgorithm is the algorithm of a generated key when RenewRequest.Alg is empty: an
	// asymmetric key that resource servers can verify from the JWKS.
	DefaultAlgorithm = signing.AlgEdDSA
	// DefaultLifetime is what storekeys.DefaultExpiry() resolves to for a key's lifetime.
	DefaultLifetime = 90 * 24 * time.Hour
	// DefaultOverlap is what storekeys.DefaultExpiry() resolves to for a rotation overlap: how long
	// a retired key keeps verifying tokens it signed.
	DefaultOverlap = 24 * time.Hour
	// MaxOverlap caps a rotation overlap, so a retired key always stops verifying within a month.
	MaxOverlap = 30 * 24 * time.Hour
)

var (
	// ErrInvalidConfig reports a zero or duplicated static key, or a TenantConfig without a store
	// or KEK, or with a negative capacity.
	ErrInvalidConfig = errors.New("keys: invalid key manager configuration")
	// ErrUnknownKey reports a key id that the tenant does not have, or whose key no longer
	// verifies: past its NotAfter or its rotation overlap.
	ErrUnknownKey = errors.New("keys: unknown key id")
	// ErrStaticKeys reports a provisioning, import or revocation call on a Manager built by
	// NewStatic: static keys change only by redeploying with other keys.
	ErrStaticKeys = errors.New("keys: static keys cannot be provisioned, imported or revoked")
	// ErrUnsupportedAlgorithm reports an algorithm other than EdDSA, ES256, RS256 and HS256.
	ErrUnsupportedAlgorithm = errors.New("keys: unsupported signing algorithm")
	// ErrOverlapTooLong reports a rotation overlap longer than MaxOverlap (X-16).
	ErrOverlapTooLong = errors.New("keys: rotation overlap exceeds MaxOverlap")
)

// Manager signs and verifies with either static keys or per-tenant keys from the keys store; the
// constructors are the sealed choice. It is safe for concurrent use. A tenant Manager's cache
// trusts its entries only while its poller, run by Start, keeps up; otherwise every call reads the
// store and fails with revoke.ErrUnavailable when the store cannot answer.
type Manager struct {
	static *staticKeys
	tenant *tenantKeys
}

type staticKeys struct {
	active    signing.Signer
	verifiers map[string]signing.Verifier
	published []signing.Verifier
}

type tenantKeys struct {
	store storekeys.Store
	kek   kek.KEK
	clk   clock.Clock
	cache *revoke.Keys[*keyset]
}

// NewStatic returns a Manager that signs every tenant's tokens with active and also verifies
// tokens signed by verifyOnly, for a rotation. It returns ErrInvalidConfig for a zero key or two
// keys sharing a key id.
func NewStatic(active signing.Signer, verifyOnly ...signing.Verifier) (*Manager, error) {
	if active.IsZero() {
		return nil, errors.Join(ErrInvalidConfig, errors.New("keys: zero active signer"))
	}
	all := append([]signing.Verifier{active.Verifier()}, verifyOnly...)
	if err := signing.CheckKeyIDs(all...); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	s := &staticKeys{active: active, verifiers: make(map[string]signing.Verifier, len(all))}
	for _, v := range all {
		s.verifiers[v.KeyID()] = v
		if !v.Symmetric() {
			s.published = append(s.published, v)
		}
	}
	return &Manager{static: s}, nil
}

// TenantConfig configures NewTenant. Store and KEK are required. The zero Clock reads the wall
// clock; the composition root passes the library clock. Events receives RevocationUnavailable. A
// zero Capacity selects revoke.DefaultCapacity tenants.
type TenantConfig struct {
	Store    storekeys.Store
	KEK      kek.KEK
	Clock    clock.Clock
	Events   event.Sink
	Capacity int
}

// String redacts the KEK, so formatting a config never renders key material.
func (c TenantConfig) String() string {
	return "keys.TenantConfig{KEK: REDACTED, Capacity: " + strconv.Itoa(c.Capacity) + "}"
}

// GoString renders like String.
func (c TenantConfig) GoString() string { return c.String() }

// LogValue renders like String.
func (c TenantConfig) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kek", "REDACTED"), slog.Int("capacity", c.Capacity))
}

// NewTenant returns a stopped Manager over per-tenant keys. It returns ErrInvalidConfig for a
// missing store or KEK, or a negative capacity.
func NewTenant(cfg TenantConfig) (*Manager, error) {
	if cfg.Store == nil || cfg.KEK == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("keys: tenant keys need a store and a KEK"))
	}
	t := &tenantKeys{store: cfg.Store, kek: cfg.KEK, clk: cfg.Clock}
	cache, err := revoke.NewKeys(cfg.Store, t.load, revoke.Config{Clock: cfg.Clock, Events: cfg.Events, Capacity: cfg.Capacity})
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	t.cache = cache
	return &Manager{tenant: t}, nil
}

// Signer returns the key that signs t's tokens now. A tenant Manager returns
// storekeys.ErrNoActiveKey when t has no active key, and revoke.ErrUnavailable when the store or
// the KEK cannot answer.
func (m *Manager) Signer(ctx context.Context, t principal.TenantID) (signing.Signer, error) {
	if m.static != nil {
		return m.static.active, nil
	}
	ks, err := m.tenant.keyset(ctx, t)
	if err != nil {
		return signing.Signer{}, err
	}
	s, ok := ks.signerAt(m.tenant.clk.Now())
	if !ok {
		return signing.Signer{}, storekeys.ErrNoActiveKey
	}
	return s, nil
}

// Verifier returns the key that verifies tokens of t carrying kid. It returns ErrUnknownKey when
// t has no such key or it no longer verifies, and revoke.ErrUnavailable when the store or the KEK
// cannot answer. A static Manager ignores t.
func (m *Manager) Verifier(ctx context.Context, t principal.TenantID, kid string) (signing.Verifier, error) {
	if m.static != nil {
		if v, ok := m.static.verifiers[kid]; ok {
			return v, nil
		}
		return signing.Verifier{}, ErrUnknownKey
	}
	ks, err := m.tenant.keyset(ctx, t)
	if err != nil {
		return signing.Verifier{}, err
	}
	if v, ok := ks.verifierAt(kid, m.tenant.clk.Now()); ok {
		return v, nil
	}
	return signing.Verifier{}, ErrUnknownKey
}

// Published returns t's asymmetric keys that still verify, for the JWKS; HS256 keys are never
// published. It returns revoke.ErrUnavailable when the store or the KEK cannot answer.
func (m *Manager) Published(ctx context.Context, t principal.TenantID) ([]signing.Verifier, error) {
	if m.static != nil {
		return append([]signing.Verifier(nil), m.static.published...), nil
	}
	ks, err := m.tenant.keyset(ctx, t)
	if err != nil {
		return nil, err
	}
	return ks.publishedAt(m.tenant.clk.Now()), nil
}

// Start runs the keyset poller until Stop; see revoke. It does nothing for static keys.
func (m *Manager) Start() {
	if m.tenant != nil {
		m.tenant.cache.Start()
	}
}

// Stop ends the poller and waits for it. It is idempotent.
func (m *Manager) Stop() {
	if m.tenant != nil {
		m.tenant.cache.Stop()
	}
}

// Poll reads the key change feed once; Start calls it every revoke.PollInterval. It returns
// revoke.ErrUnavailable when the feed cannot be read.
func (m *Manager) Poll(ctx context.Context) error {
	if m.tenant == nil {
		return nil
	}
	return m.tenant.cache.Poll(ctx)
}

// Ready returns revoke.ErrStale while the keyset poller lags by PollBound or more. Static keys
// are always ready.
func (m *Manager) Ready() error {
	if m.tenant == nil {
		return nil
	}
	return m.tenant.cache.Ready()
}

// String names the kind of keys only; key material never renders.
func (m *Manager) String() string {
	if m != nil && m.static != nil {
		return "keys.Manager{static " + m.static.active.String() + "}"
	}
	return "keys.Manager{tenant}"
}

// GoString renders like String.
func (m *Manager) GoString() string { return m.String() }

// LogValue renders like String.
func (m *Manager) LogValue() slog.Value { return slog.StringValue(m.String()) }

func (t *tenantKeys) keyset(ctx context.Context, tn principal.TenantID) (*keyset, error) {
	ks, err := t.cache.Get(ctx, tn)
	if err != nil {
		return nil, err
	}
	return ks, nil
}
