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
// ActiveSigningKey returns the key new tokens for tenantID are signed with; VerificationKeys
// returns every key that may still verify a token for tenantID (active plus retired-but-unexpired),
// keyed by key id. tenantID "" is the single-tenant partition.
type KeyStore interface {
	ActiveSigningKey(ctx context.Context, tenantID string) (TenantKey, error)
	VerificationKeys(ctx context.Context, tenantID string) (map[string]TenantKey, error)
}

// TenantKey is one tenant-scoped HS256 key as seen by the jwt.Service: a key id and its raw HMAC
// secret. It is deliberately decoupled from egauth/keystore's richer SigningKey so tokens/jwt
// takes on no dependency beyond this tiny contract; an adapter converts keystore.SigningKey to
// TenantKey.
type TenantKey struct {
	// KeyID is stamped as the JWT "kid" header and used to select the key on the verify path.
	KeyID string
	// Secret is the raw HMAC signing secret (already decrypted by the KeyStore).
	Secret []byte
}

// resolveSigningKey returns the secret and kid to sign a new token for tenantID with. When a
// KeyStore is configured it resolves the tenant's active key; otherwise it returns the static
// signingKey/signingKeyID (the zero-config single-keyset path).
func (s *Service[C]) resolveSigningKey(ctx context.Context, tenantID string) (secret []byte, kid string, err error) {
	if s.keyStore == nil {
		return s.signingKey, s.signingKeyID, nil
	}
	k, err := s.keyStore.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("jwt: resolving tenant signing key: %w", err)
	}
	return k.Secret, k.KeyID, nil
}

// tenantKeyFunc returns a jwt.Keyfunc that selects the verification key for tenantID from the
// KeyStore. It enforces the same protections as the static verificationKey: HMAC-only (no "none"
// / alg-confusion) and a present "kid" header must name a known key. Tenant isolation is
// inherent — only tenantID's keys are consulted, so a token signed for another tenant fails to
// verify here.
func (s *Service[C]) tenantKeyFunc(ctx context.Context, tenantID string) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
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
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown signing key id %q for tenant", kid)
		}
		return k.Secret, nil
	}
}
