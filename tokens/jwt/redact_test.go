package jwt_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/stretchr/testify/assert"
)

// These tests confirm audit item I17: the HS256 signing secrets carried in Config and
// SigningKey must never render in fmt / slog output, even though Config is the exported
// argument a consumer naturally dumps at startup.

const (
	leakSecretKey  = "single-mode-hs256-secret-do-not-leak-me"
	leakActiveSec  = "active-rotation-secret-do-not-leak-me"
	leakRetiredSec = "retired-rotation-secret-do-not-leak-me"
)

func sampleConfig() jwt.Config[struct{}] {
	return jwt.Config[struct{}]{
		Issuer:      "egauth-test",
		SecretKey:   leakSecretKey,
		ActiveKeyID: "k-new",
		SigningKeys: []jwt.SigningKey{
			{KeyID: "k-new", Secret: leakActiveSec},
			{KeyID: "k-old", Secret: leakRetiredSec},
		},
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}
}

func TestConfig_RedactsSigningSecretsWhenPrinted(t *testing.T) {
	cfg := sampleConfig()
	for _, s := range []string{
		cfg.String(),
		fmt.Sprintf("%v", cfg),
		cfg.String(),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
	} {
		assert.NotContains(t, s, leakSecretKey, "single-mode SecretKey must be redacted")
		assert.NotContains(t, s, leakActiveSec, "active signing-key secret must be redacted")
		assert.NotContains(t, s, leakRetiredSec, "retired signing-key secret must be redacted")
		assert.Contains(t, s, "REDACTED")
		// Non-secret identifying fields stay visible to aid debugging.
		assert.Contains(t, s, "egauth-test", "Issuer is not secret and should remain")
		assert.Contains(t, s, "k-new", "KeyID / ActiveKeyID are not secret and should remain")
	}
}

func TestConfig_LogValueRedactsSigningSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("startup", "jwt_config", sampleConfig())
	out := buf.String()
	assert.NotContains(t, out, leakSecretKey)
	assert.NotContains(t, out, leakActiveSec)
	assert.NotContains(t, out, leakRetiredSec)
	assert.Contains(t, out, "REDACTED")
}

func TestSigningKey_RedactsSecretWhenPrinted(t *testing.T) {
	k := jwt.SigningKey{KeyID: "k-new", Secret: leakActiveSec}
	for _, s := range []string{
		k.String(),
		fmt.Sprintf("%v", k),
		fmt.Sprintf("%#v", k),
	} {
		assert.NotContains(t, s, leakActiveSec, "signing-key secret must be redacted")
		assert.Contains(t, s, "REDACTED")
		assert.Contains(t, s, "k-new", "the non-secret KeyID should remain for identification")
	}
}

func TestSigningKey_LogValueRedactsSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("key", "signing_key", jwt.SigningKey{KeyID: "k-new", Secret: leakActiveSec})
	out := buf.String()
	assert.NotContains(t, out, leakActiveSec)
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, "k-new")
}

func TestService_RedactsKeyMaterialWhenPrinted(t *testing.T) {
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		Issuer:     "egauth-test",
		SecretKey:  leakSecretKey,
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	keyBytes := fmt.Sprintf("%v", []byte(leakSecretKey)) // how the raw key would render as a byte slice
	for _, s := range []string{
		svc.String(),
		fmt.Sprintf("%v", svc),
		fmt.Sprintf("%+v", svc),
		fmt.Sprintf("%#v", svc),
	} {
		assert.NotContains(t, s, leakSecretKey, "signing key must not render as text")
		assert.NotContains(t, s, keyBytes, "signing key must not render as bytes")
		assert.Contains(t, s, "REDACTED")
		assert.Contains(t, s, "egauth-test", "non-secret issuer should remain")
	}
}
