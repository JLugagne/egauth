// Package examplekey generates an ephemeral signing key for the runnable examples and
// documentation snippets in this module.
//
// Examples and doc snippets in *_test.go files are rendered by go/doc on pkg.go.dev as the
// canonical usage documentation. A hardcoded key in one of them is therefore a published
// credential: a reader who copy-pastes the snippet would ship a deployment whose tokens anyone
// holding the snippet can forge. Generating the key at run time keeps the snippet runnable and
// self-contained while ensuring no usable key material is ever published.
//
// This helper exists only for examples. Production code must load its key from a secret
// manager or the environment, and every key-loading path in this module refuses the literals
// listed in tokens/jwt.DeniedSecrets.
package examplekey

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/JLugagne/egauth/tokens/jwt"
)

// New returns a fresh random HS256 signing key, hex-encoded so it cannot be mistaken for a fixed
// credential, and long enough to satisfy jwt.MinSecretKeyLength. It is deterministic only in the
// sense that every call differs, which is what makes it safe to publish the surrounding snippet.
//
// A failure to read crypto/rand is unrecoverable for a process that intends to sign tokens, so New
// panics rather than returning an error that an example would have to invent handling for.
func New() string {
	raw := make([]byte, jwt.MinSecretKeyLength)
	if _, err := rand.Read(raw); err != nil {
		panic("examplekey: reading crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(raw)
}
