package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

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
// It performs the SigningKey -> jwt.Signer projection per algorithm (HMAC secret or asymmetric
// PKCS#8 private key), keeping tokens/jwt free of any dependency on this package's richer key type.
type JWTKeyStore struct {
	mgr *Manager
}

// NewJWTKeyStore wraps mgr as a tokens/jwt.KeyStore.
func NewJWTKeyStore(mgr *Manager) *JWTKeyStore {
	return &JWTKeyStore{mgr: mgr}
}

var _ jwt.KeyStore = (*JWTKeyStore)(nil)

// ActiveSigningKey resolves the tenant's active signing key and projects it to a jwt.Signer.
func (a *JWTKeyStore) ActiveSigningKey(ctx context.Context, tenantID string) (jwt.Signer, error) {
	k, err := a.mgr.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return signerFor(k)
}

// VerificationKeys resolves the tenant's verification set and projects each entry to a jwt.Signer.
func (a *JWTKeyStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]jwt.Signer, error) {
	keys, err := a.mgr.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]jwt.Signer, len(keys))
	for id, k := range keys {
		signer, err := signerFor(k)
		if err != nil {
			return nil, err
		}
		out[id] = signer
	}
	return out, nil
}

// signerFor builds a jwt.Signer from a SigningKey whose Secret has already been KEK-opened by the
// Manager. For HS256 the Secret is the raw HMAC secret; for asymmetric algs it is the PKCS#8 DER of
// the private key. An empty Alg is treated as HS256 (backward compat).
func signerFor(k SigningKey) (jwt.Signer, error) {
	alg := k.Alg
	if alg == "" {
		alg = AlgHS256
	}
	switch alg {
	case AlgHS256:
		return jwt.NewHMACSigner(k.KeyID, k.Secret)
	case "RS256":
		priv, err := x509.ParsePKCS8PrivateKey(k.Secret)
		if err != nil {
			return nil, fmt.Errorf("keystore: parsing key %q: %w", k.KeyID, err)
		}
		rk, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("keystore: key %q is not RSA", k.KeyID)
		}
		return jwt.NewRSASigner(k.KeyID, rk)
	case "ES256", "ES384", "ES512":
		priv, err := x509.ParsePKCS8PrivateKey(k.Secret)
		if err != nil {
			return nil, fmt.Errorf("keystore: parsing key %q: %w", k.KeyID, err)
		}
		ek, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("keystore: key %q is not ECDSA", k.KeyID)
		}
		signer, err := jwt.NewECDSASigner(k.KeyID, ek)
		if err != nil {
			return nil, err
		}
		// NewECDSASigner derives the alg from the key's curve; cross-check it against the stored
		// Alg so a corrupt or hand-written row (e.g. Alg "ES256" alongside a P-384 key) is rejected
		// rather than silently signing/publishing under a mismatched curve-derived alg.
		if got := signer.Method().Alg(); got != alg {
			return nil, fmt.Errorf("keystore: key %q stored alg %q does not match its curve-derived alg %q", k.KeyID, alg, got)
		}
		return signer, nil
	case "EdDSA":
		priv, err := x509.ParsePKCS8PrivateKey(k.Secret)
		if err != nil {
			return nil, fmt.Errorf("keystore: parsing key %q: %w", k.KeyID, err)
		}
		ed, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("keystore: key %q is not Ed25519", k.KeyID)
		}
		return jwt.NewEdDSASigner(k.KeyID, ed)
	default:
		return nil, fmt.Errorf("keystore: unsupported alg %q for key %q", alg, k.KeyID)
	}
}
