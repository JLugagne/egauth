package oauth_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/stretchr/testify/assert"
)

const (
	leakClientID     = "client-id-not-secret"
	leakClientSecret = "oauth-client-secret-do-not-leak"
)

func sampleProvider() *oauth.Provider {
	return oauth.New(
		"example",
		leakClientID,
		leakClientSecret,
		"https://idp.example.com/authorize",
		"https://idp.example.com/token",
		[]string{"openid", "email"},
		func(context.Context, *http.Client, string) (*oauth.UserInfo, error) {
			return nil, nil
		},
	)
}

func TestProvider_RedactsClientSecretWhenPrinted(t *testing.T) {
	p := sampleProvider()
	renderings := map[string]string{
		"String":   p.String(),
		"fmt %v":   fmt.Sprintf("%v", p),
		"fmt %+v":  fmt.Sprintf("%+v", p),
		"fmt %#v":  fmt.Sprintf("%#v", p),
		"value %v": fmt.Sprintf("%v", *p),
	}
	for name, out := range renderings {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, out, leakClientSecret, "client secret must be redacted")
			assert.Contains(t, out, "REDACTED")
			// Non-secret identifying fields stay visible to aid debugging.
			assert.Contains(t, out, "example", "provider name is not secret and should remain")
			assert.Contains(t, out, leakClientID, "client ID is not secret and should remain")
		})
	}
}

func TestProvider_LogValueRedactsClientSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("provider", "provider", sampleProvider())
	out := buf.String()
	assert.NotContains(t, out, leakClientSecret)
	assert.Contains(t, out, "REDACTED")
	assert.Contains(t, out, leakClientID)
}
