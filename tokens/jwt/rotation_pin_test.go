package jwt_test

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

// TestRotate_PinsKindAcrossRotations proves the principal kind survives refresh rotation. The
// ClaimsProvider returns claims with NO Kind (the ordinary application provider), so the value
// must be replayed from the refresh family — otherwise a Service-kind credential silently becomes
// a human one after a single rotation and a RequireMachine / RequireHuman gate flips.
func TestRotate_PinsKindAcrossRotations(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), 24*time.Hour)

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{
		Subject: uuid.Must(uuid.NewV7()),
		Kind:    egauth.Service,
	})
	require.NoError(t, err)

	current := pair
	for i := 1; i <= 3; i++ {
		current, err = svc.Rotate(ctx, "", current.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, egauth.Service, current.Claims.Kind, "rotation %d must preserve Claims.Kind", i)

		claims, verr := svc.VerifyAccessTokenForTenant(ctx, "", current.AccessToken)
		require.NoError(t, verr)
		assert.Equal(t, egauth.Service, claims.Kind, "rotation %d must stamp the kind on the access token", i)
	}

	// The gate must still hold after N rotations.
	machineOnly := tokens.RequireAuth[struct{}](svc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) { w.WriteHeader(http.StatusOK) },
		tokens.RequireMachine[struct{}](),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+current.AccessToken)
	rec := httptest.NewRecorder()
	machineOnly.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "a Service credential must still pass RequireMachine after rotation")
}

// TestRotate_PinsSubject proves a ClaimsProvider that returns a DIFFERENT subject cannot re-point
// a rotation family at another user: the descendant token keeps the family's subject.
func TestRotate_PinsSubject(t *testing.T) {
	ctx := context.Background()
	victim := uuid.Must(uuid.NewV7())
	attacker := uuid.Must(uuid.NewV7())

	store := memory.NewStore[struct{}]()
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      store,
		SecretKey:  "rotation-pin-secret-aaaaaaaaaaaaa!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, _ uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: attacker, TenantID: tenantID}, nil
		}),
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: victim})
	require.NoError(t, err)

	rotated, err := svc.Rotate(ctx, "", pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, victim, rotated.Claims.Subject, "rotation must keep the family's subject")

	claims, err := svc.VerifyAccessTokenForTenant(ctx, "", rotated.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, victim, claims.Subject, "the rotated access token must not be re-pointed at another user")
}

// TestIssueAPIKey_StampsKind proves an API-key-backed credential carries its principal kind on
// its claims, which is what the WithRequiredKind gate reads. Without it the gate is useless for
// keys: every key reads as a plain human principal.
func TestIssueAPIKey_StampsKind(t *testing.T) {
	ctx := context.Background()
	svc, _ := newRotatingService(t, okProvider(t), time.Hour)
	createdBy := uuid.Must(uuid.NewV7())

	service, err := svc.IssueAPIKey(ctx, "sk_", tokens.KeyTypeService, createdBy, tokens.Claims[struct{}]{})
	require.NoError(t, err)
	assert.Equal(t, egauth.Service, service.Claims.Kind, "a Service key must be stamped as a machine principal")

	serviceClaims, err := svc.VerifyAPIKey(ctx, "", service.Token)
	require.NoError(t, err)
	assert.Equal(t, egauth.Service, serviceClaims.Kind, "the stamped kind must survive the store round-trip")

	pat, err := svc.IssueAPIKey(ctx, "pat_", tokens.KeyTypePAT, createdBy, tokens.Claims[struct{}]{})
	require.NoError(t, err)
	assert.Equal(t, egauth.PAT, pat.Claims.Kind, "a PAT must be stamped as a PAT principal")

	patClaims, err := svc.VerifyAPIKey(ctx, "", pat.Token)
	require.NoError(t, err)
	assert.Equal(t, egauth.PAT, patClaims.Kind)
}
