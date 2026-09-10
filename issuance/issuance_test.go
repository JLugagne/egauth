package issuance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capturingIssuer(captured *tokens.Claims[struct{}]) *issuertest.MockIssuer[struct{}] {
	return &issuertest.MockIssuer[struct{}]{
		IssueTokenPairFunc: func(_ context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
			*captured = claims
			return &tokens.TokenPair[struct{}]{
				AccessToken:           "access",
				RefreshToken:          "refresh",
				RefreshTokenExpiresAt: time.Now().Add(time.Hour),
				Claims:                claims,
			}, nil
		},
	}
}

func staticResolver(state issuance.State) issuance.Resolver {
	return issuance.ResolverFunc(func(_ context.Context, _ string, _ uuid.UUID) (issuance.State, error) {
		return state, nil
	})
}

type staticGate struct{ enrolled bool }

func (g staticGate) IsEnrolled(_ context.Context, _ string, _ uuid.UUID) (bool, error) {
	return g.enrolled, nil
}

func TestNew_RequiresIssuer(t *testing.T) {
	_, err := issuance.New[struct{}](nil, issuance.WithResolver(staticResolver(issuance.State{})))
	assert.ErrorIs(t, err, issuance.ErrNilIssuer)
}

func TestNew_RequiresAuthoritativeResolver(t *testing.T) {
	var captured tokens.Claims[struct{}]
	_, err := issuance.New[struct{}](capturingIssuer(&captured))
	assert.ErrorIs(t, err, issuance.ErrMissingResolver)
}

// An MFA gate whose account-lifecycle validator (the resolver) is missing must fail
// construction, not skip the check at runtime.
func TestNew_MFAGateWithoutValidatorFailsConstruction(t *testing.T) {
	var captured tokens.Claims[struct{}]
	_, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithMFAGate(staticGate{enrolled: true}))
	assert.ErrorIs(t, err, issuance.ErrMFAWithoutValidator)
}

func TestIssue_AuthoritativeMustChangeCannotBeCleared(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(staticResolver(issuance.State{
		UserID:             uid,
		TenantID:           "acme",
		MustChangePassword: true,
	})))
	require.NoError(t, err)

	res, err := pipe.Issue(context.Background(), issuance.Request[struct{}]{
		TenantID: "acme",
		UserID:   uid,
		Method:   "password",
	})
	require.NoError(t, err)
	assert.True(t, res.MustChangePassword)
	assert.True(t, captured.MustChangePassword)
	assert.Equal(t, uid, captured.Subject)
	assert.Equal(t, "acme", captured.TenantID)
}

func TestIssue_CallerMustChangeIsPreserved(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(staticResolver(issuance.State{
		UserID:   uid,
		TenantID: "acme",
	})))
	require.NoError(t, err)

	res, err := pipe.Issue(context.Background(), issuance.Request[struct{}]{
		TenantID:           "acme",
		UserID:             uid,
		MustChangePassword: true,
	})
	require.NoError(t, err)
	assert.True(t, res.MustChangePassword)
	assert.True(t, captured.MustChangePassword)
}

func TestIssue_RejectsDeletedAndDisabledAccounts(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	for name, state := range map[string]issuance.State{
		"deleted":  {UserID: uid, TenantID: "acme", Deleted: true},
		"disabled": {UserID: uid, TenantID: "acme", Disabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			var captured tokens.Claims[struct{}]
			pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(staticResolver(state)))
			require.NoError(t, err)
			_, err = pipe.Issue(context.Background(), issuance.Request[struct{}]{TenantID: "acme", UserID: uid})
			require.Error(t, err)
			assert.Empty(t, captured.Subject, "no token may be minted for a rejected account")
		})
	}
}

func TestIssue_RejectsTenantMismatch(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(staticResolver(issuance.State{
		UserID:   uid,
		TenantID: "other",
	})))
	require.NoError(t, err)

	_, err = pipe.Issue(context.Background(), issuance.Request[struct{}]{TenantID: "acme", UserID: uid})
	require.ErrorIs(t, err, issuance.ErrTenantMismatch)
	assert.Empty(t, captured.Subject)
}

func TestIssue_RejectsUserMismatch(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	other := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(staticResolver(issuance.State{
		UserID:   other,
		TenantID: "acme",
	})))
	require.NoError(t, err)

	_, err = pipe.Issue(context.Background(), issuance.Request[struct{}]{TenantID: "acme", UserID: uid})
	require.ErrorIs(t, err, issuance.ErrUserMismatch)
	assert.Empty(t, captured.Subject)
}

func TestIssue_MFAGate_EnrolledInterim(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured),
		issuance.WithResolver(staticResolver(issuance.State{UserID: uid, TenantID: "acme"})),
		issuance.WithMFAGate(staticGate{enrolled: true}),
	)
	require.NoError(t, err)

	res, err := pipe.Issue(context.Background(), issuance.Request[struct{}]{
		TenantID: "acme",
		UserID:   uid,
		AMR:      []string{tokens.AMRPassword},
	})
	require.NoError(t, err)
	assert.True(t, res.Interim)
	assert.Equal(t, []string{tokens.AMRPassword}, captured.AMR)
	assert.False(t, captured.ExpiresAt.IsZero(), "interim token must carry a short explicit expiry")
}

func TestIssue_MFAVerifiedBypassesGate(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured),
		issuance.WithResolver(staticResolver(issuance.State{UserID: uid, TenantID: "acme"})),
		issuance.WithMFAGate(staticGate{enrolled: true}),
	)
	require.NoError(t, err)

	res, err := pipe.Issue(context.Background(), issuance.Request[struct{}]{
		TenantID:    "acme",
		UserID:      uid,
		AMR:         []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA},
		MFAVerified: true,
	})
	require.NoError(t, err)
	assert.False(t, res.Interim)
	assert.True(t, captured.ExpiresAt.IsZero())
}

func TestIssue_ResolverErrorFailsIssuance(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	wantErr := errors.New("store unavailable")
	var captured tokens.Claims[struct{}]
	pipe, err := issuance.New[struct{}](capturingIssuer(&captured), issuance.WithResolver(issuance.ResolverFunc(
		func(_ context.Context, _ string, _ uuid.UUID) (issuance.State, error) {
			return issuance.State{}, wantErr
		},
	)))
	require.NoError(t, err)

	_, err = pipe.Issue(context.Background(), issuance.Request[struct{}]{TenantID: "acme", UserID: uid})
	require.ErrorIs(t, err, wantErr)
	assert.Empty(t, captured.Subject)
}
