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
// Invariant de sécurité :
// Deux comptes distincts ayant des identifiants numériques différents sur le fournisseur OAuth/OIDC
// (notamment des identifiants 64 bits ou formats Snowflake dépassant 2^53 = 9007199254740992,
// tels que 9007199254740992 et 9007199254740993) DOIVENT impérativement produire des
// ProviderID distincts et préserver la valeur exacte sans perte de précision.
//
// Comportement vulnérable actuel :
// Dans oauth.GetJSON / gitlabFetcher / stringifyID, la désérialisation JSON standard dans un
// champ 'any' sans json.Decoder.UseNumber() convertit les nombres en float64.
// En raison de la limite de 53 bits de mantisse de la norme IEEE 754, l'entier 9007199254740993
// est arrondi à 9007199254740992. Les deux utilisateurs reçoivent alors exactement le même
// ProviderID ("9007199254740992"), provoquant une collision et une usurpation de compte complète (ATO).
func TestGitLab_IDCollision_Float64PrecisionLoss(t *testing.T) {
	ctx := context.Background()

	// Compteur pour simuler deux utilisateurs consécutifs lors des requêtes userinfo
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
				// Utilisateur 1 (Victime) : ID = 2^53 = 9007199254740992
				_, _ = w.Write([]byte(`{"sub": 9007199254740992, "email": "victim@gitlab.example.com", "name": "Victim"}`))
			} else {
				// Utilisateur 2 (Attaquant) : ID = 2^53 + 1 = 9007199254740993
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

	// Échange pour la victime (sub: 9007199254740992)
	victimInfo, err := p.Exchange(ctx, "auth-code-1", "https://app.example.com/callback", "verifier-1")
	require.NoError(t, err, "Exchange pour la victime devrait réussir")
	require.NotNil(t, victimInfo)
	assert.Equal(t, "9007199254740992", victimInfo.ProviderID, "Le ProviderID de la victime doit être 9007199254740992")

	// Échange pour l'attaquant (sub: 9007199254740993)
	attackerInfo, err := p.Exchange(ctx, "auth-code-2", "https://app.example.com/callback", "verifier-2")
	require.NoError(t, err, "Exchange pour l'attaquant devrait réussir")
	require.NotNil(t, attackerInfo)

	// INVARIANT VIOLE :
	// 1. L'identifiant de l'attaquant doit être préservé fidèlement ("9007199254740993")
	assert.Equal(t, "9007199254740993", attackerInfo.ProviderID,
		"SEC-OAU-01: le ProviderID de l'attaquant ne doit pas perdre de précision et valoir 9007199254740993")

	// 2. Les deux ProviderID doivent impérativement être distincts pour éviter l'usurpation de compte
	assert.NotEqual(t, victimInfo.ProviderID, attackerInfo.ProviderID,
		"SEC-OAU-01: deux identifiants numériques GitLab distincts ne doivent pas entrer en collision")
}
