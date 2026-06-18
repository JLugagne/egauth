package jwt

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// KeyStore resolves per-tenant signing material so a single jwt.Service can sign and verify with
// a different keyset per tenant — the seam for per-tenant cryptographic isolation. The
// egauth/keystore.Manager satisfies it. It is OPTIONAL: a Service with no KeyStore configured
// uses its static keyset (the zero-config single-tenant mode), unchanged.
//
// ActiveSigningKey returns the Signer new tokens for tenantID are signed with; VerificationKeys
// returns every Signer that may still verify a token for tenantID (active plus retired-but-unexpired),
// keyed by key id. tenantID "" is the single-tenant partition. A Signer pins its own algorithm, so
// a tenant's keyset may be HMAC or asymmetric (RS256/ES256/.../EdDSA).
type KeyStore interface {
	ActiveSigningKey(ctx context.Context, tenantID string) (Signer, error)
	VerificationKeys(ctx context.Context, tenantID string) (map[string]Signer, error)
}

// resolveSigningKey returns the Signer to sign a new token for tenantID with. When a KeyStore is
// configured it resolves the tenant's active key; otherwise it returns the static active signer
// (the zero-config single-keyset path).
func (s *Service[C]) resolveSigningKey(ctx context.Context, tenantID string) (Signer, error) {
	if s.keyStore == nil {
		return s.active, nil
	}
	signer, err := s.keyStore.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("jwt: resolving tenant signing key: %w", err)
	}
	return signer, nil
}

// tenantKeyFunc returns a jwt.Keyfunc that selects the verification Signer for tenantID from the
// KeyStore. It resolves the Signer by the token's "kid" header BEFORE consulting the alg, then pins
// token.Method.Alg() to that signer's algorithm — the same alg-confusion defense as the static
// verificationKey, now permitting asymmetric tenant keys. A KeyStore-backed service stamps a kid on
// every token, so a kid-less token is rejected. Tenant isolation is inherent: only tenantID's keys
// are consulted, so a token signed for another tenant fails to verify here.
func (s *Service[C]) tenantKeyFunc(ctx context.Context, tenantID string) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		keys, err := s.keyStore.VerificationKeys(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("jwt: resolving tenant verification keys: %w", err)
		}
		rawKid, present := token.Header["kid"]
		if !present {
			return nil, errors.New("jwt: token has no kid; a KeyStore-backed service stamps a kid on every token")
		}
		kid, ok := rawKid.(string)
		if !ok || kid == "" {
			return nil, errors.New("malformed kid header")
		}
		signer, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown signing key id %q for tenant", kid)
		}
		if token.Method.Alg() != signer.Method().Alg() {
			return nil, fmt.Errorf("unexpected signing method %q for key %q", token.Method.Alg(), kid)
		}
		return signer.VerifyKey(), nil
	}
}
