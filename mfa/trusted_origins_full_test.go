package mfa_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestHandlers_WithTrustedOrigins_AcceptsFullOrigin pins issue #124 for the MFA handlers.
func TestHandlers_WithTrustedOrigins_AcceptsFullOrigin(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	store := memory.NewStore()
	svc := mfa.NewService(store, mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	h := mfa.EnrollHandler(svc, resolver, mfa.WithTrustedOrigins("https://app.example.com"))
	req := mfaPost(url.Values{"account": {"user@example.com"}})
	req.Host = "api.example.com" // not the allowlisted host
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code, "a full-origin entry must pass the origin check")
}

// TestHandlers_WithTrustedOrigins_FullOriginLookalikeStillRejected pins exact matching.
func TestHandlers_WithTrustedOrigins_FullOriginLookalikeStillRejected(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	store := memory.NewStore()
	svc := mfa.NewService(store, mfa.WithClock(clk.now), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())
	resolver := mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) { return uid, "t1", true })

	h := mfa.EnrollHandler(svc, resolver, mfa.WithTrustedOrigins("https://app.example.com"))
	req := mfaPost(url.Values{"account": {"user@example.com"}})
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com.evil.com")

	rec := httptest.NewRecorder()
	h(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "normalization must not become suffix matching")
}
