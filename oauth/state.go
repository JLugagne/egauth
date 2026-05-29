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
	// stateSeparator joins the CSRF state and the PKCE verifier inside the state cookie. It
	// never appears in base64url output, so the two halves split unambiguously.
	stateSeparator = "."
)

// newState returns a fresh, high-entropy CSRF state value (base64url, no padding).
func newState() (string, error) {
	b := make([]byte, stateBytes)
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

// packState encodes the state and PKCE verifier into a single opaque cookie value.
func packState(state, verifier string) string {
	return state + stateSeparator + verifier
}

// unpackState splits a cookie value back into its state and verifier halves.
func unpackState(raw string) (state, verifier string, ok bool) {
	s, v, found := strings.Cut(raw, stateSeparator)
	if !found || s == "" {
		return "", "", false
	}
	return s, v, true
}

// stateMatches compares two state values in constant time.
func stateMatches(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
