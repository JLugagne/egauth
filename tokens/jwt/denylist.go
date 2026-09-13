package jwt

import (
	"bytes"
	"errors"
)

// DeniedSecrets lists the HS256 signing keys this project once published in its
// examples and SDK documentation. They are attacker-known (public on GitHub) yet
// satisfy MinSecretKeyLength, so the length gate alone cannot reject them; any
// deployment copy-pasting one would mint forgeable tokens. New, NewHMACSigner and
// Config.Validate refuse these values outright.
//
// It is exported so every other key-loading path in the module (the passkey
// ceremony-cookie key, the OAuth state-signing key, the keystore KEK) can reject
// the same published material instead of each maintaining a partial list. The
// guard in internal/securitydefaults walks the repository's examples and docs and
// fails when a literal assigned to a key field is missing from this set, so the
// list cannot silently fall behind the published surfaces again.
var DeniedSecrets = map[string]bool{
	"replace-with-a-32-byte-minimum-secret-in-production!": true,
	"super-secret-32-byte-key-here!!!":                     true,
	"a-high-entropy-secret-kept-out-of-source-control":     true,
	"super-secret-key-change-me-in-production":             true,
	"a-32-byte-minimum-hs256-signing-secret!!":             true,
}

// deniedSecretMarkers are substrings that appear in published example keys. A key
// containing one is refused even when it is not byte-identical to a listed entry,
// so a near-copy of a published example cannot slip past an exact-match denylist.
var deniedSecretMarkers = []string{
	"minimum-hs256-signing-secret",
}

// deniedSecretError reports a non-nil error when secret matches a publicly
// published example key, or contains a marker found in one. Callers must fail
// fast: a copy-pasted published key lets anyone holding the public string forge
// HS256 tokens.
func deniedSecretError(secret []byte) error {
	if DeniedSecrets[string(secret)] {
		return errors.New("published example key detected; generate a unique secret with crypto/rand or load one from a secret manager — copy-pasted published keys let anyone forge tokens")
	}
	for _, marker := range deniedSecretMarkers {
		if bytes.Contains(secret, []byte(marker)) {
			return errors.New("key contains a marker from a published example; generate a unique secret with crypto/rand or load one from a secret manager — copy-pasted published keys let anyone forge tokens")
		}
	}
	return nil
}

// trivialSecretError reports a non-nil error when secret is trivially guessable: every byte is
// zero, or the same byte value fills the whole key. Such a key is attacker-known at any length,
// so the MinSecretKeyLength gate alone cannot reject it. newHMACSignerAllowWeak and
// Config.Validate refuse these values unconditionally — InsecureAllowWeakKey suppresses only the
// minimum-length check, never this one.
func trivialSecretError(secret []byte) error {
	if len(secret) == 0 {
		return nil
	}
	first := secret[0]
	for _, b := range secret[1:] {
		if b != first {
			return nil
		}
	}
	if first == 0 {
		return errors.New("secret is all zero bytes; generate a unique secret with crypto/rand or load one from a secret manager — an all-zero key lets anyone forge tokens")
	}
	return errors.New("repeated single-byte secret detected; generate a unique secret with crypto/rand or load one from a secret manager — a trivially known key lets anyone forge tokens")
}
