package jwt

import (
	"fmt"

	"github.com/JLugagne/egauth/internal/secretpolicy"
)

// DeniedSecrets aliases the module-wide published-credential denylist. The literals moved
// to internal/secretpolicy/secretpolicy.go, where the single shared policy (trivial,
// published and near-copy rejection) lives; this alias keeps the public jwt.DeniedSecrets
// name working for every key-loading path in the module (the passkey ceremony-cookie key,
// the OAuth state-signing key, the keystore KEK) and for the internal/securitydefaults
// repository guard.
//
// It is exported so every other key-loading path can reject the same published material
// instead of each maintaining a partial list. New, NewHMACSigner and Config.Validate
// refuse these values outright through validateSecretPolicy below.
var DeniedSecrets = secretpolicy.Denied

// validateSecretPolicy applies the shared credential-material policy to an HS256 signing
// key. minLen > 0 additionally enforces the minimum-length gate; pass 0 when the caller
// suppresses the length check (Config.InsecureAllowWeakKey) — the trivial, published and
// near-copy rejections are enforced unconditionally.
//
// The returned error wraps secretpolicy.ErrTooShort, ErrTrivial, ErrPublished or
// ErrNearCopy so errors.Is keeps working across packages. Callers must fail fast: a
// copy-pasted published key lets anyone holding the public string forge HS256 tokens, and
// a trivially known key is attacker-known at any length.
func validateSecretPolicy(secret []byte, minLen int) error {
	if err := secretpolicy.Validate("HS256 signing key", secret, minLen); err != nil {
		// Keep the historical "signing secret" wording in the public error text.
		return fmt.Errorf("invalid signing secret: %w", err)
	}
	return nil
}
