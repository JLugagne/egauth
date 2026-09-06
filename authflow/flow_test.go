package authflow_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
)

// mockAccountValidator implements authflow.AccountValidator for testing.
type mockAccountValidator struct {
	validateFunc func(ctx context.Context, tenantID string, userID uuid.UUID) error
}

func (m *mockAccountValidator) ValidateAccount(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, tenantID, userID)
	}
	return nil
}

// mockMFAGate implements authflow.MFAGate for testing.
type mockMFAGate struct {
	isEnrolledFunc func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

func (m *mockMFAGate) IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	if m.isEnrolledFunc != nil {
		return m.isEnrolledFunc(ctx, tenantID, userID)
	}
	return false, nil
}

// mockSessionMinter records minting calls.
type mockSessionMinter struct {
	mintedFlows []*authflow.FlowContext
	mintFunc    func(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *authflow.FlowContext) error
}

func (m *mockSessionMinter) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *authflow.FlowContext) error {
	m.mintedFlows = append(m.mintedFlows, flow)
	if m.mintFunc != nil {
		return m.mintFunc(ctx, w, r, flow)
	}
	return nil
}

func TestAuthFlow_PasswordLogin_NoMFA_CompletesSuccessfully(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	minter := &mockSessionMinter{}
	gate := &mockMFAGate{
		isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return false, nil
		},
	}

	engine, err := authflow.NewEngine(
		secret,
		authflow.WithMFAGate(gate),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "user@example.com",
	}

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, authflow.StateCompleted, result.State)
	assert.Empty(t, result.FlowToken, "no intermediate token should be returned when flow completes")
	assert.Len(t, minter.mintedFlows, 1)
	assert.Equal(t, []string{tokens.AMRPassword}, minter.mintedFlows[0].AMR)
}

func TestAuthFlow_PasswordLogin_WithMFA_IssuesFlowTokenAndRequiresStepUp(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	minter := &mockSessionMinter{}
	gate := &mockMFAGate{
		isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil
		},
	}

	engine, err := authflow.NewEngine(
		secret,
		authflow.WithMFAGate(gate),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "user@example.com",
	}

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	// 1. Primary auth with MFA enrolled should enter StateMFAChallenged
	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, authflow.StateMFAChallenged, result.State)
	assert.NotEmpty(t, result.FlowToken, "intermediate flow token must be issued")
	assert.Empty(t, minter.mintedFlows, "no credentials must be minted prior to MFA step-up")

	// 2. Perform Step-Up with flow token
	stepUpReq := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	stepUpRec := httptest.NewRecorder()

	stepUpResult, err := engine.ProcessStepUp(ctx, stepUpRec, stepUpReq, result.FlowToken, "totp", []string{tokens.AMROTP})
	require.NoError(t, err)
	require.NotNil(t, stepUpResult)

	assert.Equal(t, authflow.StateCompleted, stepUpResult.State)
	assert.Len(t, minter.mintedFlows, 1)

	// Cumulative AMR must include initial password + totp + mfa assurance marker
	expectedAMR := []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}
	assert.ElementsMatch(t, expectedAMR, minter.mintedFlows[0].AMR)
}

func TestAuthFlow_OAuthLogin_WithMFA_PreservesOAuthAMR(t *testing.T) {
	// Proves fix for SEC-GLO-02 and AMR hardcoding: OAuth logins must enforce MFA if enrolled,
	// and step-up must retain OAuth AMR rather than falsely asserting password (pwd).
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	minter := &mockSessionMinter{}
	gate := &mockMFAGate{
		isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil
		},
	}

	engine, err := authflow.NewEngine(
		secret,
		authflow.WithMFAGate(gate),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "oauth_user@example.com",
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	rec := httptest.NewRecorder()

	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "oauth:github", []string{"oauth"}, false)
	require.NoError(t, err)
	assert.Equal(t, authflow.StateMFAChallenged, result.State)
	assert.NotEmpty(t, result.FlowToken)
	assert.Empty(t, minter.mintedFlows)

	// Complete step-up
	stepUpReq := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	stepUpRec := httptest.NewRecorder()

	stepUpResult, err := engine.ProcessStepUp(ctx, stepUpRec, stepUpReq, result.FlowToken, "totp", []string{tokens.AMROTP})
	require.NoError(t, err)
	assert.Equal(t, authflow.StateCompleted, stepUpResult.State)

	require.Len(t, minter.mintedFlows, 1)
	expectedAMR := []string{"oauth", tokens.AMROTP, tokens.AMRMFA}
	assert.ElementsMatch(t, expectedAMR, minter.mintedFlows[0].AMR)
}

func TestAuthFlow_MagicLink_WithMFA_EnforcesStepUp(t *testing.T) {
	// Proves fix for SEC-ID-03: Magic link logins must NOT bypass MFA when the user is enrolled.
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	minter := &mockSessionMinter{}
	gate := &mockMFAGate{
		isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil
		},
	}

	engine, err := authflow.NewEngine(
		secret,
		authflow.WithMFAGate(gate),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "magic@example.com",
	}

	req := httptest.NewRequest(http.MethodPost, "/magic-link/login", nil)
	rec := httptest.NewRecorder()

	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "magic_link", []string{tokens.AMROTP}, false)
	require.NoError(t, err)
	assert.Equal(t, authflow.StateMFAChallenged, result.State)
	assert.NotEmpty(t, result.FlowToken)
	assert.Empty(t, minter.mintedFlows, "must not mint tokens before second factor")
}

func TestAuthFlow_AccountLifecycleCheck_RejectsDisabledOrDeletedUser(t *testing.T) {
	// Proves fix for SEC-ID-12 & Passkey suspension bypass: Disabled accounts must be rejected immediately.
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	validator := &mockAccountValidator{
		validateFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) error {
			return identity.ErrAccountDisabled
		},
	}

	engine, err := authflow.NewEngine(
		secret,
		authflow.WithAccountValidator(validator),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "disabled@example.com",
	}

	req := httptest.NewRequest(http.MethodPost, "/passkey/login", nil)
	rec := httptest.NewRecorder()

	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "passkey", []string{"passkey"}, false)
	assert.ErrorIs(t, err, identity.ErrAccountDisabled)
	assert.Nil(t, result)
}

func TestAuthFlow_ExpiredOrTamperedFlowToken_Fails(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	engine, err := authflow.NewEngine(secret, authflow.WithTokenTTL(10*time.Millisecond))
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "user@example.com",
	}

	// Create a flow with MFA required
	gate := &mockMFAGate{isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) { return true, nil }}
	engineWithGate, _ := authflow.NewEngine(secret, authflow.WithMFAGate(gate), authflow.WithTokenTTL(10*time.Millisecond))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	res, err := engineWithGate.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{"pwd"}, false)
	require.NoError(t, err)

	// Wait for token expiry
	time.Sleep(20 * time.Millisecond)

	stepUpReq := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	stepUpRec := httptest.NewRecorder()

	_, err = engine.ProcessStepUp(ctx, stepUpRec, stepUpReq, res.FlowToken, "totp", []string{"otp"})
	assert.ErrorIs(t, err, authflow.ErrFlowTokenExpired)

	// Tampered token
	_, err = engine.ProcessStepUp(ctx, stepUpRec, stepUpReq, res.FlowToken+"invalid", "totp", []string{"otp"})
	assert.ErrorIs(t, err, authflow.ErrInvalidFlowToken)
}

func TestAuthFlow_ForcedPasswordChange_PropagatedToSession(t *testing.T) {
	ctx := context.Background()
	secret := []byte("01234567890123456789012345678901")

	minter := &mockSessionMinter{}
	engine, err := authflow.NewEngine(
		secret,
		authflow.WithMinter(minter),
		authflow.WithPasswordPolicyChecker(func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil // must change password
		}),
	)
	require.NoError(t, err)

	user := &identity.User{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Email:    "user@example.com",
	}

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	result, err := engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false)
	require.NoError(t, err)
	assert.Equal(t, authflow.StateCompleted, result.State)

	require.Len(t, minter.mintedFlows, 1)
	assert.True(t, minter.mintedFlows[0].MustChangePassword)
}
