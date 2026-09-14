package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
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

// stateBucket is the set of values carried through the authorization round trip inside the signed
// state cookie. Every field is authenticated by the HMAC, so the callback can trust them.
type stateBucket struct {
	State string
	// Verifier is the PKCE code verifier.
	Verifier string
	// Nonce is the OIDC nonce bound to this attempt.
	Nonce string
	// Provider is the provider name that started the flow, so a cookie minted for one provider
	// cannot be replayed against another's callback.
	Provider string
	// Tenant is the tenant that started the flow, for the same reason across tenants.
	Tenant string
	// RedirectURI is the redirect target ADVERTISED on the authorization request. Binding it means
	// the token exchange uses the exact value the provider was given, instead of re-deriving one:
	// two derivations can disagree (and both can depend on the request Host), and the binding would
	// otherwise rest entirely on the provider's own check.
	RedirectURI string
	// IssuedAt is when the flow started. It is signed so it cannot be back-dated, which is what
	// makes WithStateTTL a server-side property rather than a client-side cookie lifetime.
	IssuedAt int64
}

// stateFieldCount is the number of base64url-encoded fields in a packed state, excluding the
// trailing signature.
const stateFieldCount = 7

// packState encodes a stateBucket plus an HMAC-SHA256 signature over the encoded fields.
//
// The signed payload is the concatenation of the encoded fields; the signature is the last field.
// Signing the encoded form (rather than a re-serialization) means a decoder cannot be tricked by
// differing encodings of the same logical value.
func packState(b stateBucket, key []byte) string {
	fields := []string{
		enc(b.State),
		enc(b.Verifier),
		enc(b.Nonce),
		enc(b.Provider),
		enc(b.Tenant),
		enc(b.RedirectURI),
		enc(strconv.FormatInt(b.IssuedAt, 10)),
	}
	payload := strings.Join(fields, stateSeparator)
	if len(key) == 0 {
		// No key: the caller's validate() rejects this configuration. Returning the unsigned payload
		// keeps the failure at the configuration check rather than here.
		return payload
	}
	return payload + stateSeparator + computeStateHMAC(payload, key)
}

// unpackState verifies the signature and decodes the bucket. It fails closed with ok=false when no
// key is configured, when the shape is wrong, or when the signature does not verify (SEC-OAU-03).
func unpackState(raw string, key []byte) (stateBucket, bool) {
	if len(key) == 0 {
		// STATE-01 fail closed: a state cookie with no verification key can never be trusted.
		return stateBucket{}, false
	}
	parts := strings.Split(raw, stateSeparator)
	if len(parts) != stateFieldCount+1 || parts[0] == "" {
		return stateBucket{}, false
	}
	payload := strings.Join(parts[:stateFieldCount], stateSeparator)
	if !stateMatches(parts[stateFieldCount], computeStateHMAC(payload, key)) {
		return stateBucket{}, false
	}
	decode := func(i int) (string, bool) {
		// The empty string is a legitimate value for optional fields (no nonce, single tenant,
		// an empty redirect URI); a malformed encoding is not.
		if parts[i] == "" {
			return "", true
		}
		v, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return "", false
		}
		return string(v), true
	}
	var b stateBucket
	for i, dst := range []*string{&b.State, &b.Verifier, &b.Nonce, &b.Provider, &b.Tenant, &b.RedirectURI} {
		v, ok := decode(i)
		if !ok {
			return stateBucket{}, false
		}
		*dst = v
	}
	rawIssued, ok := decode(stateFieldCount - 1)
	if !ok {
		return stateBucket{}, false
	}
	issuedAt, err := strconv.ParseInt(rawIssued, 10, 64)
	if err != nil {
		return stateBucket{}, false
	}
	b.IssuedAt = issuedAt
	return b, true
}

// enc base64url-encodes one field. RawURLEncoding output never contains the separator.
func enc(v string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(v))
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
