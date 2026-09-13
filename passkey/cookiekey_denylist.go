package passkey

import (
	"bytes"
	"errors"

	"github.com/JLugagne/egauth/tokens/jwt"
)

// deniedCookieKeys lists the ceremony-cookie HMAC keys this project once published in
// its examples and SDK documentation. They are attacker-known (public on GitHub) yet
// satisfy MinCookieKeyLength, so the length gate alone cannot reject them; any
// deployment copy-pasting one would let anyone holding the public string forge
// ceremony-cookie state. NewService and the handler-layer key resolution refuse these
// values outright.
//
// cookieKeyError also consults jwt.DeniedSecrets, so a literal published as a signing key
// cannot be reused as a ceremony key. The lists stay separate because a value can be a
// perfectly good 32-byte cookie key and still be a published credential.
var deniedCookieKeys = map[string]bool{
	"very-secure-32-byte-secret-key!!": true,
}

// cookieKeyError reports a non-nil error when key is all zero bytes, matches a
// publicly published example key, or is one of the signing keys denied by tokens/jwt.
// Callers must fail fast: an all-zero or copy-pasted published key lets anyone holding
// the public string forge ceremony cookies.
func cookieKeyError(key []byte) error {
	if bytes.Equal(key, make([]byte, len(key))) {
		return errors.New("passkey: Config.CookieKey is all zero bytes; generate a unique key with crypto/rand or load one from a secret manager — an all-zero key lets anyone forge ceremony cookies")
	}
	if deniedCookieKeys[string(key)] || jwt.DeniedSecrets[string(key)] {
		return errors.New("passkey: published example cookie key detected; generate a unique key with crypto/rand or load one from a secret manager — copy-pasted published keys let anyone forge ceremony cookies")
	}
	return nil
}
