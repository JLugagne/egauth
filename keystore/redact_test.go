package keystore_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/stretchr/testify/assert"
)

// A SigningKey handed back by the Manager carries the OPENED (plaintext) key material, so any
// %v/%+v/%s of a struct holding one — a log line, a debug dump, an error wrapping a value — must
// never render it. The redaction mirrors tokens/redact.go.
func TestSigningKey_RedactsSecretWhenPrinted(t *testing.T) {
	const secret = "super-secret-signing-material"
	key := keystore.SigningKey{
		KeyID:     "kid-1",
		TenantID:  "acme",
		Alg:       keystore.AlgHS256,
		Secret:    []byte(secret),
		CreatedAt: time.Unix(1_700_000_000, 0),
	}

	// A []byte field renders as decimal bytes under %v/%+v, which is a full disclosure of the key
	// even though it is not the literal string: both renderings must be gone.
	asBytes := fmt.Sprintf("%v", []byte(secret))

	for _, s := range []string{
		key.String(),
		fmt.Sprintf("%v", key),
		fmt.Sprintf("%+v", key),
		fmt.Sprintf("%s", key),
		fmt.Sprintf("%#v", key),
		fmt.Sprintf("%v", &key),
		fmt.Sprintf("%v", keystore.Keyset{TenantID: "acme", Active: key, Verify: map[string]keystore.SigningKey{"kid-1": key}}),
		fmt.Sprintf("%+v", keystore.Keyset{TenantID: "acme", Active: key, Verify: map[string]keystore.SigningKey{"kid-1": key}}),
	} {
		assert.NotContains(t, s, secret, "plaintext signing material leaked into printed output")
		assert.NotContains(t, s, asBytes, "plaintext signing material leaked as a byte slice")
		assert.Contains(t, s, "REDACTED")
	}
	// The non-secret identifiers stay visible: redaction must not make logs useless.
	assert.Contains(t, key.String(), "kid-1")
	assert.Contains(t, key.String(), "acme")
}

func TestSigningKey_LogValueRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("resolved", "key", keystore.SigningKey{KeyID: "kid-1", TenantID: "acme", Secret: []byte("leak-me")})
	out := buf.String()
	assert.NotContains(t, out, "leak-me")
	assert.Contains(t, out, "REDACTED")
}
