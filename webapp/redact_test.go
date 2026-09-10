package webapp_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
)

const leakSigningKey = "webapp-hs256-signing-key-do-not-leak"

func sampleConfig() webapp.Config {
	return webapp.Config{
		SigningKey:     leakSigningKey,
		Issuer:         "example-app",
		Tenant:         "acme",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		TrustedOrigins: []string{"app.example.com"},
	}
}

func TestConfig_RedactsSigningKeyWhenPrinted(t *testing.T) {
	cfg := sampleConfig()
	renderings := map[string]string{
		"String":  cfg.String(),
		"fmt %v":  fmt.Sprintf("%v", cfg),
		"fmt %+v": fmt.Sprintf("%+v", cfg),
		"fmt %#v": fmt.Sprintf("%#v", cfg),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, leakSigningKey, "SigningKey must be redacted")
			assert.Contains(t, out, "REDACTED")
			// Non-secret identifying fields stay visible to aid debugging.
			assert.Contains(t, out, "example-app", "Issuer is not secret and should remain")
			assert.Contains(t, out, "acme", "Tenant is not secret and should remain")
		})
	}
}

func TestConfig_LogValueRedactsSigningKey(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("startup", "config", sampleConfig())
	out := buf.String()
	assert.NotContains(t, out, leakSigningKey)
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, "example-app")
}
