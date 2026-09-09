package httputil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/httputil"
)

// TestNormalizeHosts pins the accepted formats (full origins and bare hosts are equivalent)
// and the exact-match safety of the shared allowlist normalizer.
func TestNormalizeHosts(t *testing.T) {
	accepted := []struct {
		name    string
		entries []string
		want    []string
	}{
		{name: "full origin", entries: []string{"https://app.example.com"}, want: []string{"app.example.com"}},
		{name: "full origin with port", entries: []string{"https://app.example.com:8443"}, want: []string{"app.example.com:8443"}},
		{name: "full origin with path and query", entries: []string{"https://app.example.com/app/?x=1"}, want: []string{"app.example.com"}},
		{name: "bare host", entries: []string{"app.example.com"}, want: []string{"app.example.com"}},
		{name: "bare host with port", entries: []string{"app.example.com:8443"}, want: []string{"app.example.com:8443"}},
		{name: "uppercase host is lowercased", entries: []string{"HTTPS://APP.Example.COM"}, want: []string{"app.example.com"}},
		{name: "mixed forms", entries: []string{"https://app.example.com", "api.example.com"}, want: []string{"app.example.com", "api.example.com"}},
		{name: "surrounding space is trimmed", entries: []string{"  https://app.example.com  "}, want: []string{"app.example.com"}},
		{name: "empty list", entries: nil, want: []string{}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			got, err := httputil.NormalizeHosts(tc.entries)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	rejected := []struct {
		name    string
		entries []string
	}{
		{name: "unparseable", entries: []string{":://bad"}},
		{name: "path only", entries: []string{"/path-only"}},
		{name: "empty entry", entries: []string{""}},
		{name: "whitespace only", entries: []string{"   "}},
		{name: "bare host with path", entries: []string{"app.example.com/admin"}},
		{name: "userinfo", entries: []string{"user@app.example.com"}},
		{name: "valid entry after invalid one", entries: []string{"app.example.com", ":://bad"}},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, err := httputil.NormalizeHosts(tc.entries)
			require.Error(t, err)
		})
	}
}
