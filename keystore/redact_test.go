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

const leakKeySecret = "keystore-hmac-secret-do-not-leak!!"

func sampleSigningKey() keystore.SigningKey {
	return keystore.SigningKey{
		KeyID:     "k-new",
		TenantID:  "acme",
		Alg:       keystore.AlgHS256,
		Secret:    []byte(leakKeySecret),
		CreatedAt: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
}

func TestSigningKey_RedactsSecretWhenPrinted(t *testing.T) {
	k := sampleSigningKey()
	renderings := map[string]string{
		"String":  k.String(),
		"fmt %v":  fmt.Sprintf("%v", k),
		"fmt %+v": fmt.Sprintf("%+v", k),
		"fmt %#v": fmt.Sprintf("%#v", k),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, leakKeySecret, "Secret must be redacted")
			assert.NotContains(t, out, fmt.Sprintf("%v", []byte(leakKeySecret)), "Secret must not render as bytes")
			assert.Contains(t, out, "REDACTED")
			// Non-secret metadata stays visible to aid debugging.
			assert.Contains(t, out, "k-new", "KeyID is not secret and should remain")
			assert.Contains(t, out, "acme", "TenantID is not secret and should remain")
		})
	}
}

func TestKeyset_RedactsSigningSecretsWhenPrinted(t *testing.T) {
	ks := keystore.Keyset{
		TenantID: "acme",
		Active:   sampleSigningKey(),
		Verify:   map[string]keystore.SigningKey{"k-new": sampleSigningKey()},
	}
	renderings := map[string]string{
		"String":  ks.String(),
		"fmt %v":  fmt.Sprintf("%v", ks),
		"fmt %+v": fmt.Sprintf("%+v", ks),
		"fmt %#v": fmt.Sprintf("%#v", ks),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, leakKeySecret, "Secrets must be redacted")
			assert.Contains(t, out, "REDACTED")
			assert.Contains(t, out, "k-new")
		})
	}
}

func TestSigningKey_LogValueRedactsSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("key", "signing_key", sampleSigningKey())
	out := buf.String()
	assert.NotContains(t, out, leakKeySecret)
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, "k-new")
}
