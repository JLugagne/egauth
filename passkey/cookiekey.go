package passkey

import (
	"context"

	"github.com/JLugagne/egauth/internal/secretpolicy"
)

// CookieKeyResolver returns the ceremony-cookie HMAC key to use for a given tenant. It is the seam
// that makes the passkey ceremony cookie tenant-scoped: see WithTenantCookieKeys. tenantID is the
// empty string for the single-tenant partition. Implementations must return a stable, random secret
// of at least MinCookieKeyLength bytes; returning an error fails the request closed rather than
// falling back to a shared key.
type CookieKeyResolver func(ctx context.Context, tenantID string) ([]byte, error)

// cookieKeyError applies the shared credential-material policy (internal/secretpolicy) to a
// ceremony-cookie HMAC key. A key shorter than MinCookieKeyLength, an all-zero or
// single-repeated-byte key, a credential published in this project's examples/docs, or a
// near-copy of one is refused: each is guessable or attacker-known, so it would let anyone
// forge the ceremony cookie that carries the challenge and the user-verification requirement.
// The policy lives in one place so every key-loading path shares it; do not add a private
// denylist here.
func cookieKeyError(key []byte) error {
	return secretpolicy.Validate("passkey ceremony-cookie key", key, MinCookieKeyLength)
}
