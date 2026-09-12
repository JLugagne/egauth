package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithTrustedOrigins_AcceptsFullOrigin pins issue #124: a consumer wiring the handler
// directly must be able to pass the documented full-origin form and have it match.
func TestWithTrustedOrigins_AcceptsFullOrigin(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithTrustedOrigins("https://app.example.com"))
	req := postWithRefresh(pair.RefreshToken)
	req.Host = "api.example.com" // not the allowlisted host: only normalization can save it
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code, "a full-origin entry must match the bare Origin host")
}

// TestWithTrustedOrigins_FullOriginLookalikeStillRejected pins that normalizing the
// allowlist does not weaken exact matching.
func TestWithTrustedOrigins_FullOriginLookalikeStillRejected(t *testing.T) {
	svc, _ := newRotator(t)
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	h := tokens.RefreshHandler[struct{}](svc, tokens.WithTrustedOrigins("https://app.example.com"))
	req := postWithRefresh(pair.RefreshToken)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com.evil.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "normalization must not become suffix matching")
}
