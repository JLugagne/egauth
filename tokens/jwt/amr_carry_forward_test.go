package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for F-COMP-004: stepped-up assurance (AMR and auth_time) must
// survive a silent refresh. The rotation path re-derives claims from the ClaimsProvider,
// which by design returns no AMR; the family's recorded assurance is the fallback, so a
// legitimately elevated session keeps satisfying tokens.WithRequiredAMR(AMRMFA).

func TestRotate_CarriesAMRForwardWhenClaimsProviderOmitsIt(t *testing.T) {
	ctx := context.Background()
	svc, store := newRotatingService(t, okProvider(t), 24*time.Hour)
	uid := uuid.Must(uuid.NewV7())
	authTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	amr := []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject:  uid,
		AMR:      amr,
		AuthTime: authTime,
	})
	require.NoError(t, err)

	// The minted family record must persist the assurance so descendants can inherit it.
	initial, err := store.FindRefreshToken(ctx, "", tokens.HashToken(pair.RefreshToken))
	require.NoError(t, err)
	assert.ElementsMatch(t, amr, initial.AMR, "the refresh-token record must persist the family's AMR")

	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.ElementsMatch(t, amr, claims.AMR,
		"the refreshed access token must keep the family's AMR when the ClaimsProvider returns none")
	assert.WithinDuration(t, authTime, claims.AuthTime, 2*time.Second,
		"auth_time must survive rotation")

	// The successor record must carry the assurance forward as well.
	successor, err := store.FindRefreshToken(ctx, "", tokens.HashToken(rotated.RefreshToken))
	require.NoError(t, err)
	assert.ElementsMatch(t, amr, successor.AMR,
		"the rotated refresh-token record must keep the family's AMR")
}

func TestRotate_LegacyRecordWithoutAMRStillRotates(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	// A legacy record carries no AMR (the field predates it); rotation must keep working.
	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7())})
	require.NoError(t, err)

	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err, "a family with no recorded AMR must still rotate")

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.Empty(t, claims.AMR, "rotation must not manufacture assurance for a legacy family")
}

func TestRotate_ClaimsProviderAMRWinsOverRecordedAMR(t *testing.T) {
	ctx := context.Background()
	// A provider that re-evaluates assurance still wins; only an omitted (empty) AMR falls
	// back to the family's recorded value.
	provider := tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID, AMR: []string{tokens.AMRPassword}}, nil
	})
	svc, _ := newRotatingService(t, provider, 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
		AMR:     []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA},
	})
	require.NoError(t, err)

	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{tokens.AMRPassword}, claims.AMR,
		"provider-supplied AMR must override the family fallback (re-evaluation, not freezing)")
}
