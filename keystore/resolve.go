package keystore

import (
	"context"
	"errors"
	"time"
)

// ActiveSigningKey returns the tenant's current active signing key with its secret decrypted,
// ready for tokens/jwt to sign with. It returns ErrNoActiveKey if the tenant has no active key
// (e.g. after RevokeTenantKeys) and ErrTenantNotFound if the tenant was never provisioned.
//
// tenantID "" is the single-tenant partition.
func (m *Manager) ActiveSigningKey(ctx context.Context, tenantID string) (SigningKey, error) {
	key, err := m.store.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		if m.lazy && errors.Is(err, ErrTenantNotFound) {
			if perr := m.ProvisionTenant(ctx, tenantID); perr != nil {
				return SigningKey{}, perr
			}
			key, err = m.store.ActiveSigningKey(ctx, tenantID)
		}
		if err != nil {
			return SigningKey{}, err
		}
	}
	if err := m.openKey(&key); err != nil {
		return SigningKey{}, err
	}
	return key, nil
}

// VerificationKeys returns every key that may still verify a token for the tenant — the active
// key plus any retired-but-unexpired keys — keyed by KeyID, each with its secret decrypted. This
// is what tokens/jwt consults on the verify path so a token signed by a just-rotated key keeps
// validating during the overlap window.
func (m *Manager) VerificationKeys(ctx context.Context, tenantID string) (map[string]SigningKey, error) {
	keys, err := m.store.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]SigningKey, len(keys))
	for id, k := range keys {
		if err := m.openKey(&k); err != nil {
			return nil, err
		}
		out[id] = k
	}
	return out, nil
}

// Keyset resolves the full signing material for a tenant in one call: the active signer plus the
// verification set, all decrypted. It is the convenience entry point for tokens/jwt's per-request
// keyset resolution.
func (m *Manager) Keyset(ctx context.Context, tenantID string) (Keyset, error) {
	active, err := m.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return Keyset{}, err
	}
	verify, err := m.VerificationKeys(ctx, tenantID)
	if err != nil {
		return Keyset{}, err
	}
	// Defensive: ensure the active key is always in the verification set.
	if _, ok := verify[active.KeyID]; !ok {
		verify[active.KeyID] = active
	}
	return Keyset{TenantID: tenantID, Active: active, Verify: verify}, nil
}

// openKey decrypts key.Secret in place from its KEK-sealed form. Stores hold the sealed bytes in
// SigningKey.Secret; the Manager opens them here before any signing material leaves the package.
func (m *Manager) openKey(key *SigningKey) error {
	pt, err := m.kek.Open(key.Secret, []byte(key.TenantID))
	if err != nil {
		return err
	}
	key.Secret = pt
	return nil
}

// SealSecret seals a plaintext secret with the Manager's KEK. Store backends call it (indirectly,
// via the keys the Manager hands them already sealed) — it is exported so adapters and the
// conformance suite can construct sealed key material without reaching into the KEK directly.
func (m *Manager) SealSecret(plaintext []byte, tenantID ...string) ([]byte, error) {
	if len(tenantID) > 0 {
		return m.kek.Seal(plaintext, []byte(tenantID[0]))
	}
	return m.kek.Seal(plaintext)
}

// NotAfter returns the NotAfter of a tenant's active signing key — the instant past which it
// stops signing and should already have been renewed. A zero time means the active key never
// expires. It returns ErrNoActiveKey / ErrTenantNotFound like ActiveSigningKey.
func (m *Manager) NotAfter(ctx context.Context, tenantID string) (time.Time, error) {
	key, err := m.store.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return time.Time{}, err
	}
	return key.NotAfter, nil
}

// NeedsRenewal reports whether a tenant's active signing key is within window of its NotAfter (or
// already past it), so a scheduler can renew ahead of expiry for zero-downtime rollover. A key
// with no expiry never needs renewal.
func (m *Manager) NeedsRenewal(ctx context.Context, tenantID string, window time.Duration) (bool, error) {
	key, err := m.store.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if key.NotAfter.IsZero() {
		return false, nil
	}
	return !m.now().Before(key.NotAfter.Add(-window)), nil
}
