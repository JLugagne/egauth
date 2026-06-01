package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

const (
	stateBytes        = 16
	pkceVerifierBytes = 32
	nonceBytes        = 32
	// stateSeparator joins the CSRF state, the PKCE verifier and the OIDC nonce inside the
	// state cookie. It never appears in base64url output, so the parts split unambiguously.
	stateSeparator = "."
)

// newState returns a fresh, high-entropy CSRF state value (base64url, no padding).
func newState() (string, error) {
	return randomToken(stateBytes)
}

// newNonce returns a fresh, high-entropy OIDC nonce (base64url, no padding).
func newNonce() (string, error) {
	return randomToken(nonceBytes)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newPKCE returns a PKCE code verifier and its S256 challenge (RFC 7636).
func newPKCE() (verifier, challenge string, err error) {
	b := make([]byte, pkceVerifierBytes)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// packState encodes the state, PKCE verifier and OIDC nonce into a single opaque cookie value.
// The verifier and nonce may be empty (no PKCE / non-OIDC provider).
func packState(state, verifier, nonce string) string {
	return state + stateSeparator + verifier + stateSeparator + nonce
}

// unpackState splits a cookie value back into its state, verifier and nonce parts. It accepts
// the two-part legacy form (no nonce) for an in-flight cookie minted before an upgrade.
func unpackState(raw string) (state, verifier, nonce string, ok bool) {
	parts := strings.SplitN(raw, stateSeparator, 3)
	if len(parts) < 2 || parts[0] == "" {
		return "", "", "", false
	}
	state, verifier = parts[0], parts[1]
	if len(parts) == 3 {
		nonce = parts[2]
	}
	return state, verifier, nonce, true
}

// stateMatches compares two state values in constant time.
func stateMatches(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
