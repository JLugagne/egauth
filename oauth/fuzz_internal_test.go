package oauth

import "testing"

// FuzzUnpackState exercises the OAuth state-cookie decoder (SEC-12). unpackState splits and
// base64url-decodes an attacker-controlled cookie value back into its five fields; it must fail
// closed (ok=false) on any malformed shape and never panic. It is unexported, so this fuzz target
// lives in the oauth package.
func FuzzUnpackState(f *testing.F) {
	f.Add(packState("state", "verifier", "nonce", "google", "tenant-a"))
	f.Add(packState("", "", "", "", ""))
	f.Add("")
	f.Add("only-one-field")
	f.Add("a.b.c.d.e")
	f.Add("a\x00b")

	f.Fuzz(func(_ *testing.T, raw string) {
		// Must not panic; the boolean/parts are validated by unit tests elsewhere.
		_, _, _, _, _, _ = unpackState(raw)
	})
}
