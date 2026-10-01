package jwt_test

import (
	"testing"

	"github.com/JLugagne/egauth/internal/secretpolicy"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The published-key denylist and the trivial/near-copy rejection are centralized in
// internal/secretpolicy. jwt.DeniedSecrets must stay an alias of the shared map so every
// key-loading path in the module (passkey ceremony cookies, OAuth state keys, the keystore
// KEK, the securitydefaults guard) consults one policy instead of a partial per-package copy.

func TestDeniedSecretsAliasesSharedSecretPolicy(t *testing.T) {
	require.NotEmpty(t, secretpolicy.Denied)
	assert.Len(t, jwt.DeniedSecrets, len(secretpolicy.Denied),
		"jwt.DeniedSecrets must expose every entry of the shared policy")
	for key := range secretpolicy.Denied {
		assert.True(t, jwt.DeniedSecrets[key], "jwt.DeniedSecrets must be an alias of secretpolicy.Denied (%q missing)", key)
	}
}

func TestSigningKeyPolicyErrorsWrapSharedSentinels(t *testing.T) {
	_, err := jwt.NewHMACSigner("k1", []byte("a-32-byte-minimum-hs256-signing-secret!!"))
	require.Error(t, err, "a published example key must be rejected")
	assert.ErrorIs(t, err, secretpolicy.ErrPublished)

	_, err = jwt.NewHMACSigner("k1", make([]byte, jwt.MinSecretKeyLength))
	require.Error(t, err, "an all-zero key must be rejected")
	assert.ErrorIs(t, err, secretpolicy.ErrTrivial)

	_, err = jwt.NewHMACSigner("k1", []byte("prefix-a-32-byte-minimum-hs256-signing-secret!!"))
	require.Error(t, err, "a near-copy of a published example key must be rejected")
	assert.ErrorIs(t, err, secretpolicy.ErrNearCopy)
}
