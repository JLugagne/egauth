package jwt

import "errors"

// deniedSecrets lists the HS256 signing keys this project once published in its
// examples and SDK documentation. They are attacker-known (public on GitHub) yet
// satisfy MinSecretKeyLength, so the length gate alone cannot reject them; any
// deployment copy-pasting one would mint forgeable tokens. New, NewHMACSigner and
// Config.Validate refuse these values outright.
var deniedSecrets = map[string]bool{
	"replace-with-a-32-byte-minimum-secret-in-production!": true,
	"super-secret-32-byte-key-here!!!":                     true,
}

// deniedSecretError reports a non-nil error when secret matches a publicly
// published example key. Callers must fail fast: a copy-pasted published key lets
// anyone holding the public string forge HS256 tokens.
func deniedSecretError(secret []byte) error {
	if deniedSecrets[string(secret)] {
		return errors.New("published example key detected; generate a unique secret with crypto/rand or load one from a secret manager — copy-pasted published keys let anyone forge tokens")
	}
	return nil
}
