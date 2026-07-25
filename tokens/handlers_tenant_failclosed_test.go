package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// unmappedTenant models the natural resolver for a Host it cannot map: it returns "".
func unmappedTenant(*http.Request) string { return "" }

func TestRefreshHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	var rotated atomic.Bool
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			rotated.Store(true)
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "a",
				RefreshToken:          "r",
				RefreshTokenExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot, tokens.WithTenantResolver(unmappedTenant))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("some-refresh"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, rotated.Load(), "a configured resolver returning \"\" must not rotate in the \"\" partition")
}

// tenantRecordingRevoker records the tenant every lookup/revocation is scoped to.
type tenantRecordingRevoker struct {
	tenants []string
}

func (r *tenantRecordingRevoker) FindRefreshToken(ctx context.Context, tenantID, tokenHash string) (*tokens.RefreshToken, error) {
	r.tenants = append(r.tenants, tenantID)
	return &tokens.RefreshToken{FamilyID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7())}, nil
}

func (r *tenantRecordingRevoker) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	r.tenants = append(r.tenants, tenantID)
	return nil
}

func TestLogoutHandler_UnresolvedTenantFailsClosed(t *testing.T) {
	revoker := &tenantRecordingRevoker{}
	h := tokens.LogoutHandler(revoker, tokens.WithTenantResolver(unmappedTenant))

	req := postWithRefresh("some-refresh")
	req.URL.Path = "/auth/logout"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, revoker.tenants, "an unresolved tenant must not revoke a family in the \"\" partition")
}

func TestRefreshHandler_SingleTenantWithoutResolverStillWorks(t *testing.T) {
	rot := &issuertest.MockRotator[struct{}]{
		RotateFunc: func(ctx context.Context, tenantID string, refreshToken string) (*tokens.TokenPair[struct{}], error) {
			assert.Equal(t, "", tenantID)
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "a",
				RefreshToken:          "r",
				RefreshTokenExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	h := tokens.RefreshHandler[struct{}](rot)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postWithRefresh("some-refresh"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
}
