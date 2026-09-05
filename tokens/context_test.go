package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customClaims is a non-empty C so the round-trip proves Claims[C] (not just Actor)
// survives the context hop.
type customClaims struct {
	Role string
}

func newContextVerifier(subject uuid.UUID, tenantID string) *issuertest.MockVerifier[customClaims] {
	return &issuertest.MockVerifier[customClaims]{
		VerifyAccessTokenForTenantFunc: func(_ context.Context, _, token string) (*tokens.Claims[customClaims], error) {
			if token == "valid-token" {
				return &tokens.Claims[customClaims]{
					Subject:  subject,
					TenantID: tenantID,
					Custom:   customClaims{Role: "admin"},
				}, nil
			}
			return nil, tokens.ErrInvalidToken
		},
	}
}

func TestContextMiddleware(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	tenantID := "tenant-123"
	verifier := newContextVerifier(subject, tenantID)

	t.Run("injects actor and claims into context on valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		var gotActor egauth.Actor
		var gotActorOK bool
		var gotClaims *tokens.Claims[customClaims]
		var gotClaimsOK bool
		var nextCalled bool

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			gotActor, gotActorOK = tokens.ActorFromContext(r.Context())
			gotClaims, gotClaimsOK = tokens.ClaimsFromContext[customClaims](r.Context())
			w.WriteHeader(http.StatusOK)
		})

		tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.True(t, nextCalled, "next must be called for a valid token")

		require.True(t, gotActorOK)
		assert.Equal(t, subject, gotActor.UserID)
		assert.Equal(t, tenantID, gotActor.TenantID)

		require.True(t, gotClaimsOK)
		require.NotNil(t, gotClaims)
		assert.Equal(t, subject, gotClaims.Subject)
		assert.Equal(t, "admin", gotClaims.Custom.Role)
	})

	t.Run("fails closed without calling next when token is missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		var nextCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, nextCalled, "next must NOT be called when auth fails")
	})

	t.Run("fails closed without calling next when token is invalid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bogus")
		rec := httptest.NewRecorder()

		var nextCalled bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, nextCalled)
	})
}

// TestActorFromContext_Empty proves the accessors fail closed on a bare context (no
// middleware ran) rather than returning a zero Actor that reads as authenticated.
func TestActorFromContext_Empty(t *testing.T) {
	_, ok := tokens.ActorFromContext(context.Background())
	assert.False(t, ok)

	_, claimsOK := tokens.ClaimsFromContext[customClaims](context.Background())
	assert.False(t, claimsOK)
}

// TestClaimsFromContext_WrongType proves a ClaimsFromContext call with the wrong C fails
// closed (ok=false) instead of panicking, so a mis-typed consumer rejects rather than crashes.
func TestClaimsFromContext_WrongType(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	verifier := newContextVerifier(subject, "t1")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Actor is type-agnostic and must still resolve.
		_, actorOK := tokens.ActorFromContext(r.Context())
		assert.True(t, actorOK)
		// Wrong C: must fail closed, not panic.
		_, claimsOK := tokens.ClaimsFromContext[struct{ Other string }](r.Context())
		assert.False(t, claimsOK)
	})

	tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)
}

func TestUserResolverFromContext(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())
	tenantID := "tenant-xyz"
	verifier := newContextVerifier(subject, tenantID)

	t.Run("returns actor user and tenant after middleware", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid, tenant, ok := tokens.UserResolverFromContext(r)
			require.True(t, ok)
			assert.Equal(t, subject, uid)
			assert.Equal(t, tenantID, tenant)

			sid, sok := tokens.SubjectResolverFromContext(r)
			require.True(t, sok)
			assert.Equal(t, subject, sid)
		})

		tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)
	})

	t.Run("fails closed on a request that never passed the middleware", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, _, ok := tokens.UserResolverFromContext(req)
		assert.False(t, ok)

		_, sok := tokens.SubjectResolverFromContext(req)
		assert.False(t, sok)
	})
}

func TestClientContext(t *testing.T) {
	ctx := context.Background()

	// Initially absent
	cc, ok := tokens.ClientContextFromContext(ctx)
	assert.False(t, ok)
	assert.True(t, cc.IsEmpty())

	// Injected
	expected := tokens.ClientContext{
		IP:        "198.51.100.1",
		UserAgent: "TestAgent/1.0",
	}
	ctxWithCC := tokens.WithClientContext(ctx, expected)

	got, ok := tokens.ClientContextFromContext(ctxWithCC)
	assert.True(t, ok)
	assert.Equal(t, expected, got)
	assert.False(t, got.IsEmpty())
}
