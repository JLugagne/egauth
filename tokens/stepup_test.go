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

func stepUpService() *jwt.Service[struct{}] {
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "step-up-secret-aaaaaaaaaaaaaaaaa", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
}

func TestRequireAuth_StepUpAMRGate(t *testing.T) {
	svc := stepUpService()
	uid := uuid.New()

	issue := func(amr ...string) string {
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uid, AMR: amr})
		require.NoError(t, err)
		return pair.AccessToken
	}
	protected := func(opts ...tokens.AuthOption[struct{}]) http.HandlerFunc {
		return tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, opts...)
	}
	call := func(h http.HandlerFunc, token string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}

	t.Run("password-only token is blocked when MFA is required", func(t *testing.T) {
		code := call(protected(tokens.WithRequiredAMR[struct{}](tokens.AMRMFA)), issue(tokens.AMRPassword))
		assert.Equal(t, http.StatusForbidden, code)
	})

	t.Run("MFA token passes the gate", func(t *testing.T) {
		code := call(protected(tokens.WithRequiredAMR[struct{}](tokens.AMRMFA)), issue(tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA))
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("multiple required factors must all be present", func(t *testing.T) {
		gate := tokens.WithRequiredAMR[struct{}](tokens.AMRPassword, tokens.AMRWebAuthn)
		assert.Equal(t, http.StatusForbidden, call(protected(gate), issue(tokens.AMRPassword)))
		assert.Equal(t, http.StatusOK, call(protected(gate), issue(tokens.AMRPassword, tokens.AMRWebAuthn)))
	})

	t.Run("no requirement lets any authenticated token through", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, call(protected(), issue(tokens.AMRPassword)))
	})
}

func TestVerifyAccessToken_AMRRoundTrip(t *testing.T) {
	svc := stepUpService()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.New(),
		AMR:     []string{tokens.AMRPassword, tokens.AMRWebAuthn},
	})
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(context.Background(), "", pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMRWebAuthn}, claims.AMR)
}
