package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestWithTrustedOrigins_AcceptsFullOrigin pins issue #124 for the identity handlers.
func TestWithTrustedOrigins_AcceptsFullOrigin(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTrustedOrigins("https://app.example.com"))

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Host = "api.example.com" // not the allowlisted host
	req.Header.Set("Origin", "https://app.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code, "a full-origin entry must match the bare Origin host")
}

// TestWithTrustedOrigins_FullOriginLookalikeStillRejected pins exact matching.
func TestWithTrustedOrigins_FullOriginLookalikeStillRejected(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	h := identity.LoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithTrustedOrigins("https://app.example.com"))

	req := loginForm(t, "/login", "user@example.com", "secret", "")
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com.evil.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "normalization must not become suffix matching")
}
