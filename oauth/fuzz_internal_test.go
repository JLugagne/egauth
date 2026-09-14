package oauth

import "testing"

// FuzzUnpackState exercises the OAuth state-cookie decoder (SEC-12). unpackState splits and
// base64url-decodes an attacker-controlled cookie value back into its five fields; it must fail
// closed (ok=false) on any malformed shape and never panic. It is unexported, so this fuzz target
// lives in the oauth package.
func FuzzUnpackState(f *testing.F) {
	f.Add(packState(stateBucket{
		State: "state", Verifier: "verifier", Nonce: "nonce",
		Provider: "google", Tenant: "tenant-a", IssuedAt: 1_700_000_000,
	}, testStateKey))
	f.Add(packState(stateBucket{}, nil))
	f.Add("")
	f.Add("only-one-field")
	f.Add("a.b.c.d.e")
	f.Add("a\x00b")

	f.Fuzz(func(_ *testing.T, raw string) {
		// Must not panic; the boolean/parts are validated by unit tests elsewhere.
		_, _ = unpackState(raw, testStateKey)
	})
}
