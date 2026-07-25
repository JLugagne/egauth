package keystore

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/event"
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
	if err := m.openKey(tenantID, &key); err != nil {
		return SigningKey{}, err
	}
	return key, nil
}

// VerificationKeys returns every key that may still verify a token for the tenant — the active
// key plus any retired-but-unexpired keys — keyed by KeyID, each with its secret decrypted. This
// is what tokens/jwt consults on the verify path so a token signed by a just-rotated key keeps
// validating during the overlap window.
//
// A key row that cannot be opened with the deployment KEK (corrupt at rest, or sealed under a KEK
// that is no longer configured) is SKIPPED rather than failing the whole set, so one bad row
// cannot take a tenant's verification path — or its published JWKS — offline. Each skipped row
// emits EventKeyUnreadable so the degradation is observable. The signing path stays strict:
// ActiveSigningKey still returns the open error rather than signing with nothing.
func (m *Manager) VerificationKeys(ctx context.Context, tenantID string) (map[string]SigningKey, error) {
	keys, err := m.store.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]SigningKey, len(keys))
	for id, k := range keys {
		if err := m.openKey(tenantID, &k); err != nil {
			m.emitKeyUnreadable(ctx, tenantID, id, err)
			continue
		}
		out[id] = k
	}
	return out, nil
}

// emitKeyUnreadable reports a key row that could not be opened with the deployment KEK.
func (m *Manager) emitKeyUnreadable(ctx context.Context, tenantID, keyID string, err error) {
	event.Emit(ctx, m.events, event.Event{
		Type:     EventKeyUnreadable,
		TenantID: tenantID,
		Reason:   ReasonKeyUnsealFailed,
		Err:      err,
		Attrs:    map[string]any{"key_id": keyID},
	})
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
//
// The context bound at seal time is (tenantID, PurposeSigningKey, key id), and tenantID is the
// tenant the OPERATION is scoped to — not the one recorded on the row. A key row moved into another
// tenant's partition therefore fails to open (ErrCiphertextCorrupt) instead of handing the caller a
// foreign tenant's signing material.
func (m *Manager) openKey(tenantID string, key *SigningKey) error {
	pt, err := m.kek.Open(SigningKeyContext(tenantID, key.KeyID), key.Secret)
	if err != nil {
		return err
	}
	key.Secret = pt
	return nil
}

// SigningKeyContext returns the SecretContext a tenant's signing-key material is sealed under. Use
// it when re-sealing rows out of band (see SecretContext) or when a backend has to construct sealed
// material itself.
func SigningKeyContext(tenantID, keyID string) SecretContext {
	return SecretContext{TenantID: tenantID, Purpose: PurposeSigningKey, RowID: keyID}
}

// SealSecret seals a plaintext secret with the Manager's KEK, binding sc as associated data. Store
// backends call it (indirectly, via the keys the Manager hands them already sealed) — it is exported
// so adapters, re-sealing tooling and the conformance suite can construct sealed key material
// without reaching into the KEK directly. For signing keys, build sc with SigningKeyContext.
func (m *Manager) SealSecret(sc SecretContext, plaintext []byte) ([]byte, error) {
	return m.kek.Seal(sc, plaintext)
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
