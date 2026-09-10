package authflow

import (
	"testing"
	"time"
)

// FuzzDecodeFlowToken drives the HMAC-authenticated flow-token decoder with arbitrary,
// attacker-supplied cookie values. The token is opaque to the client, so decodeFlowToken must
// reject malformed shapes, bad signatures, unparseable payloads and expired contexts by
// returning an error — never by panicking.
func FuzzDecodeFlowToken(f *testing.F) {
	secret := []byte("authflow-fuzz-secret-0123456789")
	now := time.Unix(1_700_000_000, 0).UTC()

	valid, err := encodeFlowToken(&FlowContext{
		FlowID:        "flow-1",
		TenantID:      "tenant-a",
		State:         StateMFAChallenged,
		PrimaryFactor: "password",
		Factors:       []string{"password"},
		CreatedAt:     now,
		ExpiresAt:     now.Add(5 * time.Minute),
	}, secret)
	if err != nil {
		f.Fatalf("encodeFlowToken: %v", err)
	}

	f.Add(valid)
	f.Add(valid[:len(valid)-1]) // truncated signature
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("not-base64.not-base64")
	f.Add("eyJmbG93X2lkIjoidCJ9.") // valid-looking payload, empty signature

	f.Fuzz(func(_ *testing.T, token string) {
		_, _ = decodeFlowToken(token, secret, now)
	})
}
