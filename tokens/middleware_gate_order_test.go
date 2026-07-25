package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gateOrderService mints tokens for the gate-ordering tests.
func gateOrderService(t *testing.T) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "gate-order-secret-aaaaaaaaaaaaaaaa!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

// TestWithGate_RunsAfterPrincipalKindGate pins the documented order: the built-in principal-kind
// gate runs BEFORE the application-supplied WithGate predicate, so a wrong-kind credential is
// rejected without ever reaching application policy code.
func TestWithGate_RunsAfterPrincipalKindGate(t *testing.T) {
	svc := gateOrderService(t)

	machineToken, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
		Kind:    egauth.Service,
	})
	require.NoError(t, err)

	call := func(h http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+machineToken.AccessToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("RequireAuth", func(t *testing.T) {
		gateCalled := false
		reached := false
		h := tokens.RequireAuth[struct{}](svc,
			func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
				reached = true
				w.WriteHeader(http.StatusOK)
			},
			tokens.RequireHuman[struct{}](),
			tokens.WithGate[struct{}](func(egauth.Actor, struct{}) error {
				gateCalled = true
				return nil
			}),
		)

		rec := call(h)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
		assert.False(t, gateCalled, "the application gate must not run for a credential the kind gate rejects")
		assert.False(t, reached)
	})

	t.Run("ContextMiddleware", func(t *testing.T) {
		gateCalled := false
		h := tokens.ContextMiddleware[struct{}](svc,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			tokens.RequireHuman[struct{}](),
			tokens.WithGate[struct{}](func(egauth.Actor, struct{}) error {
				gateCalled = true
				return nil
			}),
		)

		rec := call(h)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "wrong_principal_kind")
		assert.False(t, gateCalled, "the application gate must not run for a credential the kind gate rejects")
	})
}
