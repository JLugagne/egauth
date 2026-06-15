package keystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/event"
)

// DefaultKeyTTL is the default lifetime of a freshly minted signing key when ProvisionOptions /
// RenewOptions do not specify one. A renewed (previous) key is kept verify-only for this long
// past renewal so outstanding tokens keep validating during the overlap.
const DefaultKeyTTL = 90 * 24 * time.Hour

// secretLength is the byte length of a generated HS256 secret. 32 bytes (256 bits) matches
// tokens/jwt.MinSecretKeyLength and the HMAC-SHA256 block size.
const secretLength = 32

// Manager is the Service half of the keystore contract. It wraps a Store, owns the deployment
// KEK (sealing secrets before they reach the Store and opening them after), generates key
// material, and drives the provision / renew / delete / revoke lifecycle with event emission.
//
// A Manager is the multi-tenant KeyStore an application wires into tokens/jwt. With no tenant
// ever provisioned beyond "" it degrades to the single-tenant partition; if no Manager is wired
// at all, tokens/jwt stays in its static single-keyset zero-config mode.
type Manager struct {
	store  Store
	kek    *KEK
	events event.Sink
	now    func() time.Time
	rand   func([]byte) (int, error)
	// erasers are fanned out by DeleteTenant to purge tenant-scoped records from downstream
	// stores (sessions, tokens, …) in addition to crypto material.
	erasers []TenantEraser
	// lazy, when set, makes a keyset resolution auto-provision an unknown tenant on first use
	// instead of returning ErrTenantNotFound. Off by default: provisioning is explicit.
	lazy bool
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithEventSink wires a security-event sink. Nil disables emission (the default).
func WithEventSink(sink event.Sink) ManagerOption {
	return func(m *Manager) { m.events = sink }
}

// WithClock overrides the time source (for deterministic testing). The zero value is time.Now.
func WithClock(now func() time.Time) ManagerOption {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

// WithTenantErasers registers downstream stores that DeleteTenant must also purge, so a single
// DeleteTenant call removes all tenant-scoped state (crypto + sessions + tokens + …), not just
// keys. Erasers run in registration order and must be idempotent (resumable delete).
func WithTenantErasers(erasers ...TenantEraser) ManagerOption {
	return func(m *Manager) { m.erasers = append(m.erasers, erasers...) }
}

// NewManager builds a Manager over store using kek for envelope encryption. It fails fast:
// a nil store or nil kek is a configuration error (ErrKEKRequired enforces that the KEK is
// mandatory — there is no unencrypted mode).
func NewManager(store Store, kek *KEK, opts ...ManagerOption) (*Manager, error) {
	if store == nil {
		return nil, errors.New("keystore: NewManager requires a non-nil Store")
	}
	if kek == nil {
		return nil, ErrKEKRequired
	}
	m := &Manager{
		store: store,
		kek:   kek,
		now:   time.Now,
		rand:  rand.Read,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// ProvisionOptions tune ProvisionTenant.
type ProvisionOptions struct {
	// KeyTTL overrides DefaultKeyTTL for the tenant's initial key. Zero selects the default; a
	// negative value means no expiry (NotAfter stays zero).
	KeyTTL time.Duration
	// KeyID overrides the generated initial key ID. Leave empty to auto-generate.
	KeyID string
}

// ProvisionTenant creates a tenant with a fresh active signing key. It is idempotent: if the
// tenant already exists it is a no-op success (no second key, no duplicate event). On a genuine
// first provision it emits EventTenantProvisioned.
func (m *Manager) ProvisionTenant(ctx context.Context, tenantID string, opts ...func(*ProvisionOptions)) error {
	var o ProvisionOptions
	for _, fn := range opts {
		fn(&o)
	}
	exists, err := m.store.TenantExists(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("keystore: checking tenant: %w", err)
	}
	if exists {
		return nil // idempotent
	}
	key, err := m.newKey(tenantID, o.KeyID, o.KeyTTL)
	if err != nil {
		return err
	}
	if err := m.store.CreateTenant(ctx, tenantID, key); err != nil {
		// A concurrent provision may have won the race; treat ErrTenantExists as success.
		if errors.Is(err, ErrTenantExists) {
			return nil
		}
		return fmt.Errorf("keystore: creating tenant: %w", err)
	}
	m.emit(ctx, EventTenantProvisioned, tenantID, "")
	return nil
}

// RenewOptions tune RenewSigningKey / RenewTenantKeys.
type RenewOptions struct {
	// KeyTTL is the lifetime of the new active key. Zero selects DefaultKeyTTL; negative means
	// no expiry.
	KeyTTL time.Duration
	// OverlapTTL is how long the previous key is kept verify-only past renewal. Zero selects
	// DefaultKeyTTL so outstanding tokens keep validating during a full key lifetime.
	OverlapTTL time.Duration
	// KeyID overrides the generated new key ID.
	KeyID string
}

// RenewSigningKey rolls a tenant's active signing key: it mints a new active key and keeps the
// previous one verify-only until OverlapTTL elapses (graceful, zero-downtime rollover). Tokens
// signed before renewal keep verifying during the overlap; new tokens use the new key. It emits
// EventTenantKeysRenewed.
//
// RenewSigningKey requires the tenant to exist (ErrTenantNotFound otherwise) and does not touch
// any other tenant.
func (m *Manager) RenewSigningKey(ctx context.Context, tenantID string, opts ...func(*RenewOptions)) error {
	var o RenewOptions
	for _, fn := range opts {
		fn(&o)
	}
	exists, err := m.store.TenantExists(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("keystore: checking tenant: %w", err)
	}
	if !exists {
		return ErrTenantNotFound
	}
	next, err := m.newKey(tenantID, o.KeyID, o.KeyTTL)
	if err != nil {
		return err
	}
	overlap := o.OverlapTTL
	if overlap == 0 {
		overlap = DefaultKeyTTL
	}
	retiredAt := m.now()
	// The previous key stops signing now but stays valid for verification for the overlap
	// window; RotateSigningKey caps its NotAfter so RetireExpiredKeys reaps it afterwards.
	if err := m.store.RotateSigningKey(ctx, tenantID, next, retiredAt.Add(overlap)); err != nil {
		return fmt.Errorf("keystore: rotating signing key: %w", err)
	}
	m.emit(ctx, EventTenantKeysRenewed, tenantID, "")
	return nil
}

// RenewTenantKeys is an alias of RenewSigningKey kept for the lifecycle vocabulary in the task
// contract (renew = graceful). It behaves identically.
func (m *Manager) RenewTenantKeys(ctx context.Context, tenantID string, opts ...func(*RenewOptions)) error {
	return m.RenewSigningKey(ctx, tenantID, opts...)
}

// RetireExpiredKeys reaps the tenant's retired-and-expired keys, returning how many were
// removed. It never removes the active key. Call it on a schedule (e.g. via janitor) to keep the
// verification set small.
func (m *Manager) RetireExpiredKeys(ctx context.Context, tenantID string) (int64, error) {
	n, err := m.store.RetireExpiredKeys(ctx, tenantID, m.now())
	if err != nil {
		return 0, fmt.Errorf("keystore: retiring expired keys: %w", err)
	}
	return n, nil
}

// RevokeTenantKeys immediately deletes every key for the tenant — the no-overlap, no-grace
// option for compromise response. Outstanding tokens stop verifying at once. It does not touch
// other tenants and emits EventTenantKeysRevoked. The tenant record itself remains (re-provision
// or renew to restore signing).
func (m *Manager) RevokeTenantKeys(ctx context.Context, tenantID string) error {
	if err := m.store.RevokeTenantKeys(ctx, tenantID); err != nil {
		return fmt.Errorf("keystore: revoking tenant keys: %w", err)
	}
	m.emit(ctx, EventTenantKeysRevoked, tenantID, "")
	return nil
}

// DeleteTenant purges a tenant in one auditable, idempotent, resumable operation: it fans out
// across the registered TenantErasers (sessions, tokens, …) and then removes the tenant's crypto
// material. It emits EventTenantDeleted on success. Deleting an absent tenant is a no-op
// success. A downstream eraser failure aborts before crypto deletion so the call can be retried.
func (m *Manager) DeleteTenant(ctx context.Context, tenantID string) error {
	// Fan out to downstream stores first. If any fails, abort before touching crypto so a retry
	// re-runs every eraser (they are idempotent) and crypto is only removed once all succeed.
	for i, er := range m.erasers {
		if err := er.EraseTenant(ctx, tenantID); err != nil {
			return fmt.Errorf("keystore: erasing tenant from downstream store %d: %w", i, err)
		}
	}
	if err := m.store.DeleteTenant(ctx, tenantID); err != nil {
		return fmt.Errorf("keystore: deleting tenant crypto: %w", err)
	}
	m.emit(ctx, EventTenantDeleted, tenantID, "")
	return nil
}

// PurgeTenant is a synonym of DeleteTenant kept for the lifecycle vocabulary in the task
// contract. It behaves identically.
func (m *Manager) PurgeTenant(ctx context.Context, tenantID string) error {
	return m.DeleteTenant(ctx, tenantID)
}

// newKey mints a fresh SigningKey for tenantID with a random secret. An empty keyID is
// auto-generated. ttl of 0 selects DefaultKeyTTL; a negative ttl means no expiry.
func (m *Manager) newKey(tenantID, keyID string, ttl time.Duration) (SigningKey, error) {
	secret := make([]byte, secretLength)
	if _, err := m.rand(secret); err != nil {
		return SigningKey{}, fmt.Errorf("keystore: generating secret: %w", err)
	}
	// Seal the secret with the KEK before it ever reaches the Store: backends persist only the
	// envelope-encrypted form. ActiveSigningKey/VerificationKeys open it again before use.
	sealed, err := m.kek.Seal(secret)
	if err != nil {
		return SigningKey{}, err
	}
	if keyID == "" {
		idBytes := make([]byte, 16)
		if _, err := m.rand(idBytes); err != nil {
			return SigningKey{}, fmt.Errorf("keystore: generating key id: %w", err)
		}
		keyID = base64.RawURLEncoding.EncodeToString(idBytes)
	}
	now := m.now()
	var notAfter time.Time
	switch {
	case ttl == 0:
		notAfter = now.Add(DefaultKeyTTL)
	case ttl > 0:
		notAfter = now.Add(ttl)
	default:
		notAfter = time.Time{} // no expiry
	}
	return SigningKey{
		KeyID:     keyID,
		TenantID:  tenantID,
		Secret:    sealed,
		CreatedAt: now,
		NotAfter:  notAfter,
	}, nil
}

// emit sends a lifecycle event through the configured sink (nil-safe via event.Emit).
func (m *Manager) emit(ctx context.Context, t event.Type, tenantID, reason string) {
	event.Emit(ctx, m.events, event.Event{Type: t, TenantID: tenantID, Reason: reason})
}

// WithLazyProvisioning makes the Manager auto-provision a tenant the first time its keyset is
// resolved, instead of returning ErrTenantNotFound. It is opt-in: by default provisioning is
// explicit (call ProvisionTenant), which keeps tenant creation an auditable, deliberate act.
func WithLazyProvisioning() ManagerOption {
	return func(m *Manager) { m.lazy = true }
}
