package tokens_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/stretchr/testify/assert"
)

func TestTokenPair_RedactsSecretsWhenPrinted(t *testing.T) {
	pair := tokens.TokenPair[struct{}]{
		AccessToken:      "super-secret-access",
		RefreshToken:     "super-secret-refresh",
		RefreshTokenHash: "safe-hash",
	}
	for _, s := range []string{
		pair.String(),
		fmt.Sprintf("%v", pair),
		fmt.Sprintf("%s", pair),
		fmt.Sprintf("%#v", pair),
	} {
		assert.NotContains(t, s, "super-secret-access")
		assert.NotContains(t, s, "super-secret-refresh")
		assert.Contains(t, s, "REDACTED")
	}
}

func TestTokenPair_LogValueRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("issued", "pair", tokens.TokenPair[struct{}]{AccessToken: "leak-me", RefreshToken: "leak-me-too"})
	out := buf.String()
	assert.NotContains(t, out, "leak-me")
	assert.Contains(t, out, "REDACTED")
}

func TestAPIKey_RedactsTokenWhenPrinted(t *testing.T) {
	k := tokens.APIKey[struct{}]{Token: "sk_live_supersecret", Prefix: "sk_live_", Hash: "safe-hash"}
	s := fmt.Sprintf("%v", k)
	assert.NotContains(t, s, "sk_live_supersecret")
	assert.Contains(t, s, "REDACTED")
	assert.Contains(t, s, "sk_live_", "the non-secret prefix should remain for identification")
}
