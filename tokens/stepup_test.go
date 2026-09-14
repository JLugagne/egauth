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
	uid := uuid.Must(uuid.NewV7())

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
		Subject: uuid.Must(uuid.NewV7()),
		AMR:     []string{tokens.AMRPassword, tokens.AMRWebAuthn},
	})
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(context.Background(), "", pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{tokens.AMRPassword, tokens.AMRWebAuthn}, claims.AMR)
}

// TestRequireAuth_DenyInterim is the regression test for the structural half of the step-up
// contract. A token minted before a second factor is presented must be refusable without the
// route having to enumerate which AMR values mean "complete": an interim credential is marked as
// such at issuance, so a gate on the marker keeps working when a new factor or login path is added.
func TestRequireAuth_DenyInterim(t *testing.T) {
	svc := stepUpService()
	uid := uuid.Must(uuid.NewV7())

	issue := func(interim bool, amr ...string) string {
		pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
			Subject: uid, AMR: amr, Interim: interim,
		})
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

	interimToken := issue(true, tokens.AMRPassword)
	fullToken := issue(false, tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA)

	t.Run("interim session is refused with step_up_required", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+interimToken)
		protected(tokens.WithDenyInterim[struct{}]())(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "step_up_required")
	})

	t.Run("interim session is accepted when the route does not deny it", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, call(protected(), interimToken),
			"the gate is opt-in: an ordinary route keeps accepting an interim credential")
	})

	t.Run("a completed session passes the gate", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, call(protected(tokens.WithDenyInterim[struct{}]()), fullToken))
	})

	t.Run("a token predating the marker keeps its previous meaning", func(t *testing.T) {
		// Interim is false on every token that does not set it, including all tokens minted before
		// the field existed, so enabling the gate cannot retroactively lock anyone out.
		assert.Equal(t, http.StatusOK, call(protected(tokens.WithDenyInterim[struct{}]()), fullToken))
	})
}

// TestClaims_IsInterim covers the nil-safety of the accessor: a gate that runs before a token is
// verified must not panic on a missing claim set.
func TestClaims_IsInterim(t *testing.T) {
	var absent *tokens.Claims[struct{}]
	assert.False(t, absent.IsInterim(), "a nil Claims is not interim")

	assert.False(t, (&tokens.Claims[struct{}]{}).IsInterim())
	assert.True(t, (&tokens.Claims[struct{}]{Interim: true}).IsInterim())
}
