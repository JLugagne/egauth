package egauth

import (
	"crypto/sha256"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtectAPISecretFormatIsWhatOptionalRecognises(t *testing.T) {
	secret, hash, err := newAPIKeySecret("egk")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(secret, "egk"+apiKeySeparator))
	sum := sha256.Sum256([]byte(secret))
	require.Equal(t, sum[:], hash)
	require.Equal(t, hash, apiKeyHash(secret))
	other, _, err := newAPIKeySecret("egk")
	require.NoError(t, err)
	require.NotEqual(t, secret, other)

	a := &Auth[struct{}]{cfg: Config[struct{}]{Modules: Modules{APIKeys: &APIKeyModule{Kinds: []string{"service"}, Prefix: "egk"}}}}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	require.True(t, a.apiKeyLike(req))
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJFZERTQSJ9.e30.sig")
	require.False(t, a.apiKeyLike(req))
	a.cfg.Modules.APIKeys = nil
	req.Header.Set("Authorization", "Bearer "+secret)
	require.False(t, a.apiKeyLike(req))
}

func TestProtectAPIGrantRoundTripAndIntersection(t *testing.T) {
	raw, err := encodeAPIKeyGrant([]string{"user"}, nil, []string{"g"})
	require.NoError(t, err)
	g, err := decodeAPIKeyGrant(raw)
	require.NoError(t, err)
	require.Equal(t, []string{"user"}, g.Roles)
	require.Equal(t, []string{}, g.Scopes)
	require.Equal(t, []string{"g"}, g.Groups)
	_, err = decodeAPIKeyGrant([]byte("{not json"))
	require.Error(t, err)
	empty, err := decodeAPIKeyGrant(nil)
	require.NoError(t, err)
	require.Empty(t, empty.Roles)

	require.Equal(t, []string{"a"}, intersect([]string{"a", "b"}, []string{"a", "c", "a"}))
	require.Equal(t, []string{}, intersect(nil, []string{"a"}))
}
