package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kindVerifier returns a MockVerifier whose VerifyAccessTokenForTenant always succeeds,
// returning claims with the given principal kind. The token value is used as a key to look
// up the pre-registered kind, defaulting to empty (User) when not registered.
type kindVerifier struct {
	// tokens maps raw token string → PrincipalKind so callers can register multiple tokens.
	tokens map[string]egauth.PrincipalKind
}

func newKindVerifier() *kindVerifier {
	return &kindVerifier{tokens: make(map[string]egauth.PrincipalKind)}
}

// register adds a token → kind mapping and returns the token string for use in requests.
func (kv *kindVerifier) register(token string, kind egauth.PrincipalKind) string {
	kv.tokens[token] = kind
	return token
}

func (kv *kindVerifier) VerifyAccessTokenForTenant(_ context.Context, _ string, token string) (*tokens.Claims[struct{}], error) {
	kind, ok := kv.tokens[token]
	if !ok {
		return nil, tokens.ErrInvalidToken
	}
	return &tokens.Claims[struct{}]{
		Subject:   uuid.Must(uuid.NewV7()),
		TenantID:  "tenant-1",
		Kind:      kind,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (kv *kindVerifier) VerifyRefreshToken(_ context.Context, _ string, _ string) (*tokens.Claims[struct{}], error) {
	return nil, tokens.ErrRefreshTokenNotFound
}

func (kv *kindVerifier) VerifyAPIKey(_ context.Context, _ string, _ string, _ ...event.RequestContext) (*tokens.Claims[struct{}], error) {
	return nil, tokens.ErrAPIKeyNotFound
}

func kindCall(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestWithRequiredKind is the primary unit test for the principal-kind gate.
// It verifies: wrong kind → denied, correct kind → allowed, unset → no gate.
func TestWithRequiredKind(t *testing.T) {
	kv := newKindVerifier()
	userToken := kv.register("tok-user", egauth.User)
	patToken := kv.register("tok-pat", egauth.PAT)
	serviceToken := kv.register("tok-service", egauth.Service)

	protected := func(opts ...tokens.AuthOption[struct{}]) http.HandlerFunc {
		return tokens.RequireAuth[struct{}](kv, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, opts...)
	}

	t.Run("RequireMachine rejects User token with 403", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireMachine[struct{}]()), userToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("RequireMachine rejects PAT token with 403", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireMachine[struct{}]()), patToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("RequireMachine allows Service token", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireMachine[struct{}]()), serviceToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("RequireHuman rejects Service token with 403", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireHuman[struct{}]()), serviceToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("RequireHuman allows User token", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireHuman[struct{}]()), userToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("RequireHuman allows PAT token", func(t *testing.T) {
		rec := kindCall(protected(tokens.RequireHuman[struct{}]()), patToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("WithRequiredKind(PAT) rejects User token", func(t *testing.T) {
		rec := kindCall(protected(tokens.WithRequiredKind[struct{}](egauth.PAT)), userToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("WithRequiredKind(PAT) rejects Service token", func(t *testing.T) {
		rec := kindCall(protected(tokens.WithRequiredKind[struct{}](egauth.PAT)), serviceToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("WithRequiredKind(PAT) allows PAT token", func(t *testing.T) {
		rec := kindCall(protected(tokens.WithRequiredKind[struct{}](egauth.PAT)), patToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("no kind requirement lets any authenticated token through", func(t *testing.T) {
		// WithRequiredKind not set — gate is inactive, all kinds must pass.
		for _, tok := range []string{userToken, patToken, serviceToken} {
			assert.Equal(t, http.StatusOK, kindCall(protected(), tok).Code, "token %q should pass", tok)
		}
	})

	t.Run("zero Kind (plain interactive JWT) is treated as User by RequireHuman", func(t *testing.T) {
		// Register a token with zero Kind to simulate a plain IssueTokenPair access token.
		zeroKindToken := kv.register("tok-zero-kind", "")
		rec := kindCall(protected(tokens.RequireHuman[struct{}]()), zeroKindToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("zero Kind (plain interactive JWT) is rejected by RequireMachine", func(t *testing.T) {
		zeroKindToken := kv.register("tok-zero-kind-machine", "")
		rec := kindCall(protected(tokens.RequireMachine[struct{}]()), zeroKindToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

// TestWithRequiredKind_ContextMiddleware verifies the kind gate works via ContextMiddleware,
// which uses the same serveAuthenticated path.
func TestWithRequiredKind_ContextMiddleware(t *testing.T) {
	kv := newKindVerifier()
	patToken := kv.register("tok-pat-ctx", egauth.PAT)
	serviceToken := kv.register("tok-service-ctx", egauth.Service)

	wrapped := func(opts ...tokens.AuthOption[struct{}]) http.Handler {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return tokens.ContextMiddleware[struct{}](kv, next, opts...)
	}

	t.Run("RequireMachine rejects PAT via ContextMiddleware", func(t *testing.T) {
		rec := kindCall(wrapped(tokens.RequireMachine[struct{}]()), patToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("RequireMachine allows Service via ContextMiddleware", func(t *testing.T) {
		rec := kindCall(wrapped(tokens.RequireMachine[struct{}]()), serviceToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestWithRequiredKind_ActorKindRoundTrip verifies that when the JWT Service issues an access
// token with Claims.Kind set, the middleware propagates the Kind onto the Actor and the kind
// gate enforces it correctly end-to-end using the real jwt.Service.
func TestWithRequiredKind_ActorKindRoundTrip(t *testing.T) {
	svc := scopesService() // reuse from middleware_scopes_test.go (same package)
	uid := uuid.Must(uuid.NewV7())

	// Issue an access token with Claims.Kind = PAT.
	patPair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:  uid,
		Kind:     egauth.PAT,
		IssuedAt: time.Now(),
	})
	require.NoError(t, err)

	// Issue an access token with Claims.Kind = Service.
	svcPair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:  uid,
		Kind:     egauth.Service,
		IssuedAt: time.Now(),
	})
	require.NoError(t, err)

	// Issue a plain access token (Kind zero = User).
	userPair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject:  uid,
		IssuedAt: time.Now(),
	})
	require.NoError(t, err)

	var capturedKind egauth.PrincipalKind
	handler := tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, actor egauth.Actor, _ struct{}) {
		capturedKind = actor.Kind
		w.WriteHeader(http.StatusOK)
	})

	call := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec
	}

	t.Run("PAT kind is propagated to Actor", func(t *testing.T) {
		rec := call(patPair.AccessToken)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, egauth.PAT, capturedKind)
	})

	t.Run("Service kind is propagated to Actor", func(t *testing.T) {
		rec := call(svcPair.AccessToken)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, egauth.Service, capturedKind)
	})

	t.Run("User kind (zero) is propagated to Actor as empty Kind", func(t *testing.T) {
		rec := call(userPair.AccessToken)
		require.Equal(t, http.StatusOK, rec.Code)
		// Zero Kind is left as "" (not normalised to User at the Actor level —
		// only the gate normalises it; egauth.IsHuman treats "" as User).
		assert.Equal(t, egauth.PrincipalKind(""), capturedKind)
	})

	t.Run("RequireMachine gate rejects PAT token via real JWT Service", func(t *testing.T) {
		h := tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, tokens.RequireMachine[struct{}]())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+patPair.AccessToken)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})

	t.Run("RequireHuman gate rejects Service token via real JWT Service", func(t *testing.T) {
		h := tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, tokens.RequireHuman[struct{}]())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+svcPair.AccessToken)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
	})
}

// Verify the Verifier interface is satisfied — the mock VerifyAPIKey must match the signature.
var _ tokens.Verifier[struct{}] = (*kindVerifier)(nil)

// Ensure issuertest.MockVerifier remains compatible with Verifier (compile-time guard).
var _ tokens.Verifier[struct{}] = (*issuertest.MockVerifier[struct{}])(nil)
