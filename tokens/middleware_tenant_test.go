package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequireAuthTenantAware covers the tenant-aware verification path of RequireAuth, added so
// multi-tenant consumers can bind access tokens to a per-request tenant via the HTTP middleware.
func TestRequireAuthTenantAware(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	const tenantA = "tenant-a"
	const tenantB = "tenant-b"

	// A verifier that binds the token's signed tenant to the requested one (mirroring
	// jwt.Service.VerifyAccessTokenForTenant). Verification is always tenant-scoped: a token
	// minted for one tenant fails closed when presented under another.
	newMultiTenantVerifier := func() *issuertest.MockVerifier[any] {
		return &issuertest.MockVerifier[any]{
			VerifyAccessTokenForTenantFunc: func(ctx context.Context, tenantID, token string) (*tokens.Claims[any], error) {
				// token value encodes the tenant it was minted for: "valid-<tenant>".
				switch token {
				case "valid-" + tenantA:
					if tenantID != tenantA {
						return nil, tokens.ErrTenantMismatch
					}
					return &tokens.Claims[any]{Subject: subject, TenantID: tenantA}, nil
				case "valid-" + tenantB:
					if tenantID != tenantB {
						return nil, tokens.ErrTenantMismatch
					}
					return &tokens.Claims[any]{Subject: subject, TenantID: tenantB}, nil
				default:
					return nil, tokens.ErrInvalidToken
				}
			},
		}
	}

	t.Run("multi-tenant: resolved tenant authenticates via tenant-bound path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-"+tenantA)
		rec := httptest.NewRecorder()

		var actor egauth.Actor
		var called bool
		handler := tokens.RequireAuth[any](newMultiTenantVerifier(),
			func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom any) {
				actor = a
				called = true
				w.WriteHeader(http.StatusOK)
			},
			tokens.WithAuthTenantResolver[any](func(*http.Request) string { return tenantA }),
		)

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
		assert.Equal(t, subject, actor.UserID)
		assert.Equal(t, tenantA, actor.TenantID)
	})

	t.Run("multi-tenant: unresolved tenant fails closed (401), handler not reached", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-"+tenantA)
		rec := httptest.NewRecorder()

		var called bool
		handler := tokens.RequireAuth[any](newMultiTenantVerifier(),
			func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom any) {
				called = true
				w.WriteHeader(http.StatusOK)
			},
			// Resolver cannot map the request -> returns "" -> must NOT fall open.
			tokens.WithAuthTenantResolver[any](func(*http.Request) string { return "" }),
		)

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "handler must not run when the tenant cannot be resolved")
	})

	t.Run("multi-tenant: tenant mismatch rejected (token of A presented under tenant B)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// A token minted for tenant A, but the request resolves to tenant B.
		req.Header.Set("Authorization", "Bearer valid-"+tenantA)
		rec := httptest.NewRecorder()

		var called bool
		handler := tokens.RequireAuth[any](newMultiTenantVerifier(),
			func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom any) {
				called = true
				w.WriteHeader(http.StatusOK)
			},
			tokens.WithAuthTenantResolver[any](func(*http.Request) string { return tenantB }),
		)

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "a token minted for another tenant must be rejected")
	})

	t.Run("integration: real multi-tenant jwt.Service binds and rejects cross-tenant", func(t *testing.T) {
		store := memory.NewStore[struct{}]()
		cfg := jwt.Config[struct{}]{
			Store:      store,
			SecretKey:  "mw-secret-aaaaaaaaaaaaaaaaaaaaa!", // 32 bytes
			Issuer:     "egauth-test",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 24 * time.Hour,
			ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
				return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
			}),
		}
		svc := jwt.New[struct{}](cfg)

		uid := uuid.Must(uuid.NewV7())
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
			Subject:   uid,
			TenantID:  tenantA,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
		require.NoError(t, err)

		newHandler := func(resolved string) (http.HandlerFunc, *bool) {
			called := false
			h := tokens.RequireAuth[struct{}](svc,
				func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom struct{}) {
					called = true
					w.WriteHeader(http.StatusOK)
				},
				tokens.WithAuthTenantResolver[struct{}](func(*http.Request) string { return resolved }),
			)
			return h, &called
		}

		// Correct tenant: authenticates.
		{
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			rec := httptest.NewRecorder()
			h, called := newHandler(tenantA)
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.True(t, *called)
		}

		// Wrong tenant: rejected, handler not reached.
		{
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			rec := httptest.NewRecorder()
			h, called := newHandler(tenantB)
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.False(t, *called)
		}

		// No resolver: the access token is verified against the empty tenant (""), which the
		// tenant-bound token of tenantA does not match, so the request fails closed.
		{
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			rec := httptest.NewRecorder()
			called := false
			h := tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom struct{}) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.False(t, called, "a tenant-bound token must fail closed against the empty tenant")
		}
	})

	t.Run("single-tenant: no resolver verifies against the empty tenant (unchanged behavior)", func(t *testing.T) {
		// No WithAuthTenantResolver -> the middleware calls VerifyAccessTokenForTenant with the
		// empty tenant (""), the single-tenant default partition.
		verifier := &issuertest.MockVerifier[any]{
			VerifyAccessTokenForTenantFunc: func(ctx context.Context, tenantID, token string) (*tokens.Claims[any], error) {
				if tenantID != "" {
					return nil, tokens.ErrTenantMismatch
				}
				if token == "single-valid" {
					return &tokens.Claims[any]{Subject: subject, TenantID: ""}, nil
				}
				return nil, tokens.ErrInvalidToken
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer single-valid")
		rec := httptest.NewRecorder()

		var actor egauth.Actor
		var called bool
		handler := tokens.RequireAuth[any](verifier,
			func(w http.ResponseWriter, r *http.Request, a egauth.Actor, custom any) {
				actor = a
				called = true
				w.WriteHeader(http.StatusOK)
			},
		)

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
		assert.Equal(t, subject, actor.UserID)
		assert.Equal(t, "", actor.TenantID)
	})
}
