package keystore

import (
	"context"

	"github.com/JLugagne/egauth/tokens/jwt"
)

// JWTKeyStore adapts a Manager to the tokens/jwt.KeyStore interface, so a jwt.Service can resolve
// its signing/verification keyset per tenant through this Manager. Wire it as:
//
//	svc := jwt.New(jwt.Config[C]{
//	    // ...static config still required for the single-tenant partition...
//	    KeyStore: keystore.NewJWTKeyStore(mgr),
//	})
//
// It performs the SigningKey -> jwt.TenantKey projection (key id + decrypted secret), keeping
// tokens/jwt free of any dependency on this package's richer key type.
type JWTKeyStore struct {
	mgr *Manager
}

// NewJWTKeyStore wraps mgr as a tokens/jwt.KeyStore.
func NewJWTKeyStore(mgr *Manager) *JWTKeyStore {
	return &JWTKeyStore{mgr: mgr}
}

var _ jwt.KeyStore = (*JWTKeyStore)(nil)

// ActiveSigningKey resolves the tenant's active signing key and projects it to a jwt.TenantKey.
func (a *JWTKeyStore) ActiveSigningKey(ctx context.Context, tenantID string) (jwt.TenantKey, error) {
	k, err := a.mgr.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return jwt.TenantKey{}, err
	}
	return jwt.TenantKey{KeyID: k.KeyID, Secret: k.Secret}, nil
}

// VerificationKeys resolves the tenant's verification set and projects each entry.
func (a *JWTKeyStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]jwt.TenantKey, error) {
	keys, err := a.mgr.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]jwt.TenantKey, len(keys))
	for id, k := range keys {
		out[id] = jwt.TenantKey{KeyID: k.KeyID, Secret: k.Secret}
	}
	return out, nil
}
