package jwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims_FreshAuth(t *testing.T) {
	now := time.Now()
	c := tokens.Claims[struct{}]{AuthTime: now.Add(-2 * time.Minute)}
	assert.True(t, c.FreshAuth(5*time.Minute), "within window is fresh")
	assert.False(t, c.FreshAuth(time.Minute), "outside window is stale")
	assert.True(t, c.FreshAuth(0), "no requirement always passes")

	var zero tokens.Claims[struct{}]
	assert.False(t, zero.FreshAuth(time.Minute), "a missing auth_time fails closed")
	assert.True(t, zero.FreshAuth(0))
}

func TestAuthTime_SetOnIssueAndPreservedAcrossRotate(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	// Issue with an explicit past authentication time.
	past := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), AuthTime: past})
	require.NoError(t, err)

	c1, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)
	assert.WithinDuration(t, past, c1.AuthTime, 2*time.Second, "auth_time is carried on the access token")

	// A silent refresh must NOT reset auth_time, even though IssuedAt advances.
	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)
	c2, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.WithinDuration(t, past, c2.AuthTime, 2*time.Second, "auth_time must survive rotation")
	assert.True(t, c2.IssuedAt.After(c2.AuthTime), "IssuedAt advances on refresh while auth_time stays put")
}

func TestAuthTime_DefaultsToIssueTimeForInitialPair(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)
	c, err := svc.VerifyAccessTokenForTenant(ctx, "", pair.AccessToken)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), c.AuthTime, 5*time.Second, "initial auth_time defaults to issue time")
}

// TestAuthTime_RotationOfLegacyTokenDoesNotManufactureFreshness guards the high-severity case
// the I15 review caught: a refresh token with NO auth_time (legacy / pre-migration) must not gain
// a fresh auth_time on rotation, or a silent auto-refresh would defeat the step-up gate.
func TestAuthTime_RotationOfLegacyTokenDoesNotManufactureFreshness(t *testing.T) {
	ctx := context.Background()
	svc, store := newRotatingService(t, okProvider(t), 24*time.Hour)

	// Simulate a legacy refresh token: persisted directly with a ZERO AuthTime.
	plaintext := "legacy-refresh-token-plaintext-value"
	require.NoError(t, store.SaveRefreshToken(ctx, "", &tokens.RefreshToken{
		Hash:      tokens.HashToken(plaintext),
		FamilyID:  uuid.Must(uuid.NewV7()),
		UserID:    uuid.Must(uuid.NewV7()),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		// AuthTime intentionally zero.
	}))

	rotated, err := svc.Rotate(ctx, "", plaintext)
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.True(t, claims.AuthTime.IsZero(), "rotation must not invent an auth_time for a legacy token")
	assert.False(t, claims.FreshAuth(5*time.Minute), "a legacy-rooted token must still require step-up")
}

func TestWithMaxAuthAge_StepUpGate(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	stalePair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), AuthTime: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	freshPair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	handler := tokens.RequireAuth[struct{}](svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) { w.WriteHeader(http.StatusOK) },
		tokens.WithMaxAuthAge[struct{}](5*time.Minute))

	call := func(accessToken string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sensitive", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		handler(rec, req)
		return rec
	}

	stale := call(stalePair.AccessToken)
	assert.Equal(t, http.StatusForbidden, stale.Code, "a stale authentication must be rejected")
	assert.Contains(t, stale.Body.String(), "step_up_required")

	fresh := call(freshPair.AccessToken)
	assert.Equal(t, http.StatusOK, fresh.Code, "a fresh authentication passes the step-up gate")
}

func TestWithMaxAuthAge_DisabledByDefault(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	// Even an old authentication passes when no max-auth-age is configured.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), AuthTime: time.Now().Add(-100 * time.Hour)})
	require.NoError(t, err)

	handler := tokens.RequireAuth[struct{}](svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) { w.WriteHeader(http.StatusOK) })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	handler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
