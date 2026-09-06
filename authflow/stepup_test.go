package authflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockVerifier is a FactorVerifier test double: TOTP first, recovery code as fallback — exactly
// the contract mfa.Service satisfies structurally.
type mockVerifier struct {
	totpErr       error
	recoveryErr   error
	totpCalls     int
	recoveryCalls int
	gotUserID     uuid.UUID
	gotTenant     string
}

func (m *mockVerifier) VerifyTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) error {
	m.totpCalls++
	m.gotUserID, m.gotTenant = userID, tenantID
	return m.totpErr
}

func (m *mockVerifier) VerifyRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, code string) error {
	m.recoveryCalls++
	m.gotUserID, m.gotTenant = userID, tenantID
	return m.recoveryErr
}

// challengedFlowToken drives a real engine into StateMFAChallenged and returns the signed flow
// token, so step-up tests start from a genuine challenged ceremony.
func challengedFlowToken(t *testing.T, engine *authflow.Engine, user *identity.User) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()
	result, err := engine.ProcessPrimaryAuth(context.Background(), rec, req, user, "password", []string{tokens.AMRPassword}, false)
	require.NoError(t, err)
	require.Equal(t, authflow.StateMFAChallenged, result.State)
	require.NotEmpty(t, result.FlowToken)
	return result.FlowToken
}

// stepUpRequest builds a step-up POST carrying the flow-token cookie and a code form field.
func stepUpRequest(flowToken, code string) *http.Request {
	form := url.Values{"code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authflow.DefaultFlowCookieName, Value: flowToken})
	return req
}

// stepUpEngine assembles an engine with an always-enrolled gate and a recording minter.
func stepUpEngine(t *testing.T, minter *mockSessionMinter) *authflow.Engine {
	t.Helper()
	gate := &mockMFAGate{
		isEnrolledFunc: func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	engine, err := authflow.NewEngine([]byte("01234567890123456789012345678901"),
		authflow.WithMFAGate(gate),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)
	return engine
}

// TestStepUpHandler_TOTPCompletesFlow proves the FlowToken step-up endpoint: a correct TOTP code
// against a challenged flow completes the ceremony — the minter receives the final flow with the
// accumulated AMR ([pwd, otp, mfa]) and the flow cookie is cleared.
func TestStepUpHandler_TOTPCompletesFlow(t *testing.T) {
	minter := &mockSessionMinter{}
	engine := stepUpEngine(t, minter)
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := challengedFlowToken(t, engine, user)

	v := &mockVerifier{}
	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, stepUpRequest(flowToken, "123456"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, v.totpCalls)
	assert.Equal(t, user.ID, v.gotUserID, "the verifier must be scoped to the flow token's user")
	assert.Equal(t, "tenant-1", v.gotTenant, "the verifier must be scoped to the flow token's tenant")

	require.Len(t, minter.mintedFlows, 1, "step-up must mint the final credentials")
	flow := minter.mintedFlows[0]
	assert.Equal(t, authflow.StateCompleted, flow.State)
	assert.ElementsMatch(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, flow.AMR)
	assert.Equal(t, []string{"password", "totp"}, flow.Factors)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == authflow.DefaultFlowCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "the flow-token cookie must be cleared after completion")
}

// TestStepUpHandler_RecoveryCodeFallback proves the backup path: when TOTP verification fails,
// the handler falls back to a single-use recovery code and still completes the flow.
func TestStepUpHandler_RecoveryCodeFallback(t *testing.T) {
	minter := &mockSessionMinter{}
	engine := stepUpEngine(t, minter)
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := challengedFlowToken(t, engine, user)

	v := &mockVerifier{totpErr: errors.New("totp: invalid code")}
	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, stepUpRequest(flowToken, "recovery-code"))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, v.totpCalls)
	assert.Equal(t, 1, v.recoveryCalls, "a failed TOTP must fall back to the recovery code")

	require.Len(t, minter.mintedFlows, 1)
	flow := minter.mintedFlows[0]
	assert.Equal(t, []string{"password", "recovery_code"}, flow.Factors)
	assert.ElementsMatch(t, []string{tokens.AMRPassword, tokens.AMROTP, tokens.AMRMFA}, flow.AMR)
}

// TestStepUpHandler_InvalidCodeRejected proves the gate holds: when neither TOTP nor recovery
// verification succeeds, no credentials are minted and the client gets a uniform 401.
func TestStepUpHandler_InvalidCodeRejected(t *testing.T) {
	minter := &mockSessionMinter{}
	engine := stepUpEngine(t, minter)
	user := &identity.User{ID: uuid.New(), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := challengedFlowToken(t, engine, user)

	v := &mockVerifier{
		totpErr:     errors.New("totp: invalid code"),
		recoveryErr: errors.New("recovery: invalid code"),
	}
	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, stepUpRequest(flowToken, "wrong"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, minter.mintedFlows, "a failed second factor must not mint credentials")
}

// TestStepUpHandler_MissingFlowTokenRejected proves an anonymous POST cannot reach the verifier:
// without a flow token there is no challenged ceremony to complete.
func TestStepUpHandler_MissingFlowTokenRejected(t *testing.T) {
	minter := &mockSessionMinter{}
	engine := stepUpEngine(t, minter)

	v := &mockVerifier{}
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/step-up", strings.NewReader("code=123456"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	authflow.StepUpHandler(engine, v)(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Zero(t, v.totpCalls, "the verifier must not be called without a flow token")
	assert.Empty(t, minter.mintedFlows)
}
