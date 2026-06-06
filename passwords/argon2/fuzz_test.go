package argon2_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/passwords/argon2"
)

// FuzzNeedsRehash exercises the Argon2 PHC hash-string parser (SEC-04: malformed parameters must
// be rejected, never panic). NeedsRehash splits and parses a stored hash string — which can reach
// the library from a tampered datastore — so feeding arbitrary input proves the parser is panic-free.
func FuzzNeedsRehash(f *testing.F) {
	f.Add("")
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo")
	f.Add("$argon2id$v=19$m=,t=,p=$$")
	f.Add("$argon2id$v=19$m=65536,t=3,p=2")
	f.Add("$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA")
	f.Add("not-a-phc-string")
	f.Add("$argon2id$v=99999999999999999999$m=x,t=y,p=z$@@@$###")

	h := argon2.NewHasher()
	f.Fuzz(func(_ *testing.T, hash string) {
		_ = h.NeedsRehash(hash)
	})
}

// FuzzCompare drives the same PHC decode path through Compare, which additionally base64-decodes the
// salt and digest and runs the constant-time compare. It must return an error (never panic) on any
// malformed hash.
func FuzzCompare(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo", "password")
	f.Add("", "")
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$!!!$???", "p")

	h := argon2.NewHasher()
	f.Fuzz(func(_ *testing.T, hash, password string) {
		_ = h.Compare(context.Background(), hash, password)
	})
}
