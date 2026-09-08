package tokens_test

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// Security-audit PoC (input-exposure / sensitive data exposure): live credentials must
// never render via fmt/slog paths.

func TestAuditRedact_TokenPairNeverRendersSecrets(t *testing.T) {
	tp := tokens.TokenPair[struct{}]{AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET"}
	for _, s := range []string{fmt.Sprintf("%v", tp), fmt.Sprintf("%s", tp), fmt.Sprintf("%#v", tp)} {
		if strings.Contains(s, "ACCESS-SECRET") || strings.Contains(s, "REFRESH-SECRET") {
			t.Fatalf("TokenPair leaked via fmt: %q", s)
		}
	}
	lv := tp.LogValue()
	found := false
	for _, a := range lv.Group() {
		if strings.Contains(a.Value.String(), "ACCESS-SECRET") || strings.Contains(a.Value.String(), "REFRESH-SECRET") {
			t.Fatalf("TokenPair leaked via slog: %v", a)
		}
		found = true
	}
	if !found {
		t.Fatalf("expected slog group attrs")
	}
}

func TestAuditRedact_APIKeyNeverRendersToken(t *testing.T) {
	k := tokens.APIKey[struct{}]{ID: uuid.Must(uuid.NewV7()), TenantID: "t", Prefix: "egk_", Token: "APIKEY-SECRET", Hash: "hashval"}
	for _, s := range []string{fmt.Sprintf("%v", k), fmt.Sprintf("%#v", k)} {
		if strings.Contains(s, "APIKEY-SECRET") {
			t.Fatalf("APIKey leaked via fmt: %q", s)
		}
	}
	_ = slog.Any("key", k)
	lv := k.LogValue()
	for _, a := range lv.Group() {
		if strings.Contains(a.Value.String(), "APIKEY-SECRET") {
			t.Fatalf("APIKey leaked via slog: %v", a)
		}
	}
}
