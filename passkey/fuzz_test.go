package passkey_test

import (
	"bytes"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// FuzzParseCredentialCreationResponse fuzzes the CBOR/base64 attestation decoder that the passkey
// FinishRegistrationHandler exposes to attacker-controlled POST bodies (the body is size-capped by
// DOS-01 before this decode). It must return an error — never panic — on malformed input. The decode
// itself lives in go-webauthn, but it is the parse surface this library hands untrusted bytes to.
func FuzzParseCredentialCreationResponse(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"id":"x","type":"public-key","response":{"clientDataJSON":"","attestationObject":""}}`))
	f.Add([]byte(`{"response":{"attestationObject":"oWNmbXQ"}}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(data))
	})
}

// FuzzParseCredentialRequestResponse is the assertion (login) counterpart: the CBOR/base64 decoder
// behind FinishLoginHandler. Same contract — error, not panic, on hostile input.
func FuzzParseCredentialRequestResponse(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"id":"x","type":"public-key","response":{"clientDataJSON":"","authenticatorData":"","signature":""}}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = protocol.ParseCredentialRequestResponseBody(bytes.NewReader(data))
	})
}
