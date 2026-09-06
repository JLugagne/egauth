package oauth

import (
	"crypto/hmac"
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

// packState encodes the state, PKCE verifier, OIDC nonce, provider name and tenant into a
// single opaque cookie value. If a signing key is provided, an HMAC-SHA256 signature is appended
// as the sixth field to guarantee cookie authenticity and integrity (SEC-OAU-03).
func packState(state, verifier, nonce, provider, tenant string, key ...[]byte) string {
	payload := state + stateSeparator + verifier + stateSeparator + nonce +
		stateSeparator + base64.RawURLEncoding.EncodeToString([]byte(provider)) +
		stateSeparator + base64.RawURLEncoding.EncodeToString([]byte(tenant))
	if len(key) > 0 && len(key[0]) > 0 {
		sig := computeStateHMAC(payload, key[0])
		return payload + stateSeparator + sig
	}
	return payload
}

// unpackState splits a cookie value back into its state, verifier, nonce, provider and tenant
// parts. If a signing key is provided, the cookie must have a valid HMAC-SHA256 signature;
// unsigned, tampered, or forged cookies fail closed with ok=false (SEC-OAU-03).
func unpackState(raw string, key ...[]byte) (state, verifier, nonce, provider, tenant string, ok bool) {
	parts := strings.Split(raw, stateSeparator)
	if len(key) > 0 && len(key[0]) > 0 {
		// When a signing key is configured, exactly 6 fields are required (the 5 state fields + HMAC signature).
		if len(parts) != 6 || parts[0] == "" {
			return "", "", "", "", "", false
		}
		payload := strings.Join(parts[:5], stateSeparator)
		expectedSig := computeStateHMAC(payload, key[0])
		if !stateMatches(parts[5], expectedSig) {
			return "", "", "", "", "", false
		}
	} else {
		// Legacy / unconfigured: require exactly the five fields packState writes. An old (3-field) or forged
		// cookie that does not match the expected shape fails closed.
		if len(parts) != 5 || parts[0] == "" {
			return "", "", "", "", "", false
		}
	}
	state, verifier, nonce = parts[0], parts[1], parts[2]
	rawProvider, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", "", "", "", "", false
	}
	rawTenant, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return "", "", "", "", "", false
	}
	return state, verifier, nonce, string(rawProvider), string(rawTenant), true
}

func computeStateHMAC(payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// stateMatches compares two state values in constant time.
func stateMatches(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
