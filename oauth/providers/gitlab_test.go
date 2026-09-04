package providers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitLab_IDCollision_Float64PrecisionLoss confirms SEC-OAU-01 (CVSS 9.8).
//
// Security invariant:
// Two distinct accounts with different numeric identifiers on the OAuth/OIDC provider
// (in particular 64-bit or Snowflake-format identifiers exceeding 2^53 = 9007199254740992,
// such as 9007199254740992 and 9007199254740993) MUST produce distinct ProviderIDs
// and preserve the exact value without loss of precision.
//
// Current vulnerable behaviour:
// In oauth.GetJSON / gitlabFetcher / stringifyID, standard JSON deserialisation into an
// 'any' field without json.Decoder.UseNumber() converts numbers to float64.
// Due to the 53-bit mantissa limit of the IEEE 754 standard, the integer 9007199254740993
// is rounded to 9007199254740992. Both users then receive exactly the same
// ProviderID ("9007199254740992"), causing a collision and a full account takeover (ATO).
func TestGitLab_IDCollision_Float64PrecisionLoss(t *testing.T) {
	ctx := context.Background()

	// Counter to simulate two consecutive users across userinfo requests
	var reqCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			})
		case "/oauth/userinfo":
			count := reqCount.Add(1)
			if count == 1 {
				// User 1 (Victim): ID = 2^53 = 9007199254740992
				_, _ = w.Write([]byte(`{"sub": 9007199254740992, "email": "victim@gitlab.example.com", "name": "Victim"}`))
			} else {
				// User 2 (Attacker): ID = 2^53 + 1 = 9007199254740993
				_, _ = w.Write([]byte(`{"sub": 9007199254740993, "email": "attacker@gitlab.example.com", "name": "Attacker"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := providers.GitLabSelfHosted(srv.URL, "client-id", "client-secret",
		oauth.WithInsecureURLs(),
		oauth.WithHTTPClient(srv.Client()),
	)

	// Exchange for the victim (sub: 9007199254740992)
	victimInfo, err := p.Exchange(ctx, "auth-code-1", "https://app.example.com/callback", "verifier-1")
	require.NoError(t, err, "Exchange for the victim should succeed")
	require.NotNil(t, victimInfo)
	assert.Equal(t, "9007199254740992", victimInfo.ProviderID, "The victim's ProviderID must be 9007199254740992")

	// Exchange for the attacker (sub: 9007199254740993)
	attackerInfo, err := p.Exchange(ctx, "auth-code-2", "https://app.example.com/callback", "verifier-2")
	require.NoError(t, err, "Exchange for the attacker should succeed")
	require.NotNil(t, attackerInfo)

	// INVARIANT VIOLATED:
	// 1. The attacker's identifier must be faithfully preserved ("9007199254740993")
	assert.Equal(t, "9007199254740993", attackerInfo.ProviderID,
		"SEC-OAU-01: the attacker's ProviderID must not lose precision and must equal 9007199254740993")

	// 2. Both ProviderIDs must be distinct to prevent account takeover
	assert.NotEqual(t, victimInfo.ProviderID, attackerInfo.ProviderID,
		"SEC-OAU-01: two distinct numeric GitLab identifiers must not collide")
}
