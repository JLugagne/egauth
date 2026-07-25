package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// countingStore counts SaveRefreshToken calls so a test can prove that an issuance path persisted
// no refresh-token family.
type countingStore[C any] struct {
	tokens.Store[C]
	saves atomic.Int32
}

func (s *countingStore[C]) SaveRefreshToken(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
	s.saves.Add(1)
	return s.Store.SaveRefreshToken(ctx, tenantID, rt)
}

func TestHasStepUpFactor(t *testing.T) {
	assert.False(t, tokens.HasStepUpFactor(nil))
	assert.False(t, tokens.HasStepUpFactor([]string{}))
	assert.False(t, tokens.HasStepUpFactor([]string{tokens.AMRPassword}),
		"a password alone is not a second factor")
	assert.True(t, tokens.HasStepUpFactor([]string{tokens.AMRPassword, tokens.AMROTP}))
	assert.True(t, tokens.HasStepUpFactor([]string{tokens.AMRMFA}))
	assert.True(t, tokens.HasStepUpFactor([]string{tokens.AMRWebAuthn}))
}

func TestClaims_SatisfiesStepUp(t *testing.T) {
	full := tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}}
	assert.True(t, full.SatisfiesStepUp())

	passwordOnly := tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword}}
	assert.False(t, passwordOnly.SatisfiesStepUp())

	// An interim credential never satisfies step-up, even if its AMR were to claim the factor.
	forged := tokens.Claims[struct{}]{AMR: []string{tokens.AMRMFA}, Interim: true}
	assert.False(t, forged.SatisfiesStepUp(), "an interim credential is never stepped up")
}

// TestClaims_AsInterim proves the interim stamp strips every step-up factor marker, so a consumer
// ClaimsBuilder that always sets AMRMFA cannot accidentally mint a credential that passes an AMR
// gate before the second factor was actually verified.
func TestClaims_AsInterim(t *testing.T) {
	claims := tokens.Claims[struct{}]{
		AMR: []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA, tokens.AMRWebAuthn},
	}
	interim := claims.AsInterim(5 * time.Minute)

	assert.True(t, interim.Interim)
	assert.Equal(t, []string{tokens.AMRPassword}, interim.AMR)
	assert.False(t, interim.ExpiresAt.IsZero())
	assert.False(t, interim.SatisfiesStepUp())

	// A non-positive TTL leaves the expiry to the issuer rather than minting an already-expired one.
	assert.True(t, tokens.Claims[struct{}]{}.AsInterim(0).ExpiresAt.IsZero())
}

// TestRequireAuth_RejectsInterimCredential proves the systemic enforcement: an interim credential is
// refused by EVERY route by default and admitted only where the route opts in.
func TestRequireAuth_RejectsInterimCredential(t *testing.T) {
	svc := stepUpService()
	uid := uuid.Must(uuid.NewV7())

	issue := func(claims tokens.Claims[struct{}]) string {
		claims.Subject = uid
		pair, err := svc.IssueTokenPair(context.Background(), claims)
		require.NoError(t, err)
		return pair.AccessToken
	}
	protected := func(opts ...tokens.AuthOption[struct{}]) http.HandlerFunc {
		return tokens.RequireAuth[struct{}](svc, func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
		}, opts...)
	}
	call := func(h http.HandlerFunc, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	interim := tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword}, Interim: true}

	t.Run("ordinary route refuses it", func(t *testing.T) {
		rec := call(protected(), issue(interim))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "step_up_required")
	})

	t.Run("step-up route admits it", func(t *testing.T) {
		rec := call(protected(tokens.WithInterimAllowed[struct{}]()), issue(interim))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("the AMR gate still blocks it where it is admitted", func(t *testing.T) {
		rec := call(protected(
			tokens.WithInterimAllowed[struct{}](),
			tokens.WithRequiredAMR[struct{}](tokens.AMRMFA),
		), issue(interim))
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("a full session is unaffected", func(t *testing.T) {
		rec := call(protected(), issue(tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword}}))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestVerifyAccessToken_InterimRoundTrip proves the marker survives signing and verification, so the
// enforcement cannot be defeated by the wire format dropping it.
func TestVerifyAccessToken_InterimRoundTrip(t *testing.T) {
	svc := stepUpService()
	pair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
		Interim: true,
	})
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(context.Background(), "", pair.AccessToken)
	require.NoError(t, err)
	assert.True(t, claims.Interim, "the interim marker must survive the JWT round trip")

	full, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	fullClaims, err := svc.VerifyAccessTokenForTenant(context.Background(), "", full.AccessToken)
	require.NoError(t, err)
	assert.False(t, fullClaims.Interim)
}

// TestIssueAccessToken_PersistsNoRefreshFamily proves the access-token-only path: no refresh token is
// minted and no refresh row is written, so an interim login leaves no full-RefreshTTL row behind for
// a session that was never granted.
func TestIssueAccessToken_PersistsNoRefreshFamily(t *testing.T) {
	store := &countingStore[struct{}]{Store: memory.NewStore[struct{}]()}
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "interim-access-secret-aaaaaaaaaaaa", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})

	var issuer tokens.Issuer[struct{}] = svc
	accessIssuer, ok := issuer.(tokens.AccessTokenIssuer[struct{}])
	require.True(t, ok, "jwt.Service must implement tokens.AccessTokenIssuer")

	claims := tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())}.AsInterim(5 * time.Minute)
	token, expiresAt, err := accessIssuer.IssueAccessToken(context.Background(), claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, claims.ExpiresAt.Unix(), expiresAt.Unix(), "the explicit interim expiry must win")
	assert.Equal(t, int32(0), store.saves.Load(), "no refresh-token family may be persisted")

	verified, err := svc.VerifyAccessTokenForTenant(context.Background(), "", token)
	require.NoError(t, err)
	assert.True(t, verified.Interim)
	assert.False(t, verified.AuthTime.IsZero(), "auth_time must still anchor freshness")

	// The pair path still persists exactly one row, so the refactor did not change it.
	_, err = svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	assert.Equal(t, int32(1), store.saves.Load())
}

// TestAssuranceFromContext proves the non-generic bridge the identity and mfa handlers enforce with:
// it reports the step-up and interim state of the verified credential, and fails closed on a request
// that never passed ContextMiddleware.
func TestAssuranceFromContext(t *testing.T) {
	svc := stepUpService()

	serve := func(claims tokens.Claims[struct{}], opts ...tokens.AuthOption[struct{}]) (tokens.Assurance, bool, int) {
		claims.Subject = uuid.Must(uuid.NewV7())
		pair, err := svc.IssueTokenPair(context.Background(), claims)
		require.NoError(t, err)

		var got tokens.Assurance
		var ok bool
		h := tokens.ContextMiddleware[struct{}](svc, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, ok = tokens.AssuranceResolverFromContext(r)
		}), opts...)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return got, ok, rec.Code
	}

	t.Run("stepped-up session", func(t *testing.T) {
		got, ok, _ := serve(tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}})
		require.True(t, ok)
		assert.True(t, got.StepUp)
		assert.False(t, got.Interim)
	})

	t.Run("password-only session", func(t *testing.T) {
		got, ok, _ := serve(tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword}})
		require.True(t, ok)
		assert.False(t, got.StepUp, "a password-only session must not read as stepped up")
	})

	t.Run("interim credential on a route that admits it", func(t *testing.T) {
		got, ok, code := serve(
			tokens.Claims[struct{}]{AMR: []string{tokens.AMRPassword}, Interim: true},
			tokens.WithInterimAllowed[struct{}]())
		require.Equal(t, http.StatusOK, code)
		require.True(t, ok)
		assert.True(t, got.Interim)
		assert.False(t, got.StepUp)
	})

	t.Run("unauthenticated request fails closed", func(t *testing.T) {
		_, ok := tokens.AssuranceFromContext(context.Background())
		assert.False(t, ok, "callers must be able to tell that no assurance is available")
	})
}
