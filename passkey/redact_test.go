package passkey_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/stretchr/testify/assert"
)

var leakCookieKey = []byte("passkey-ceremony-cookie-key-do-not-leak")

func sampleConfig() passkey.Config {
	return passkey.Config{
		RPID:          "example.com",
		RPDisplayName: "Example Inc",
		RPOrigins:     []string{"https://example.com"},
		CookieKey:     leakCookieKey,
	}
}

func TestConfig_RedactsCookieKeyWhenPrinted(t *testing.T) {
	cfg := sampleConfig()
	renderings := map[string]string{
		"String":  cfg.String(),
		"fmt %v":  fmt.Sprintf("%v", cfg),
		"fmt %+v": fmt.Sprintf("%+v", cfg),
		"fmt %#v": fmt.Sprintf("%#v", cfg),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, string(leakCookieKey), "CookieKey must be redacted")
			assert.NotContains(t, out, fmt.Sprintf("%v", leakCookieKey), "CookieKey must not render as bytes")
			assert.Contains(t, out, "REDACTED")
			// Non-secret relying-party settings stay visible to aid debugging.
			assert.Contains(t, out, "example.com", "RPID is not secret and should remain")
		})
	}
}

func TestConfig_LogValueRedactsCookieKey(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("startup", "config", sampleConfig())
	out := buf.String()
	assert.NotContains(t, out, string(leakCookieKey))
	assert.NotContains(t, out, fmt.Sprintf("%v", leakCookieKey))
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, "example.com")
}
