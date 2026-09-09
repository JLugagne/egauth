// Tests for issue #120: an MFA-gated authflow engine must fail closed on the account
// lifecycle — by construction (NewEngine refuses a MFAGate without an AccountValidator)
// and at request time (ProcessStepUp refuses to mint when the validator went missing).
package authflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
)

const lifecycleTestSecret = "01234567890123456789012345678901"

// lifecycleGate is an MFAGate double with a fixed enrollment answer.
type lifecycleGate struct{ enrolled bool }

func (g lifecycleGate) IsEnrolled(context.Context, string, uuid.UUID) (bool, error) {
	return g.enrolled, nil
}

// lifecycleValidator is an AccountValidator double whose outcome is a scripted sequence:
// each ValidateAccount call consumes the next entry; once the script is exhausted the
// validator allows (the account is alive). Scripting models the issue's timeline: the
// account passes the primary-auth check, then is disabled mid-flow.
type lifecycleValidator struct{ script []error }

func (v *lifecycleValidator) ValidateAccount(context.Context, string, uuid.UUID) error {
	if len(v.script) == 0 {
		return nil
	}
	err := v.script[0]
	v.script = v.script[1:]
	return err
}

// lifecycleMinter records credential minting so refusals can be pinned on the minter
// never seeing a completed flow.
type lifecycleMinter struct{ minted []*FlowContext }

func (m *lifecycleMinter) Mint(_ context.Context, _ http.ResponseWriter, _ *http.Request, flow *FlowContext) error {
	m.minted = append(m.minted, flow)
	return nil
}

// lifecycleChallenge drives a real engine to StateMFAChallenged and returns the signed
// flow token, so lifecycle tests start from a genuine challenged ceremony.
func lifecycleChallenge(t *testing.T, engine *Engine, user *identity.User) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	result, err := engine.ProcessPrimaryAuth(context.Background(), rec, req, user, "password", []string{tokens.AMRPassword}, false)
	require.NoError(t, err)
	require.Equal(t, StateMFAChallenged, result.State)
	return result.FlowToken
}

// TestNewEngine_MFAGateWithoutAccountValidatorFailsConstruction proves the
// fail-closed-by-construction rule (issue #120): a zero-config engine that gates logins on
// MFA but carries no AccountValidator would let a challenged flow mint final credentials
// for an account disabled or soft-deleted after the challenge. NewEngine must refuse that
// wiring loudly instead of tolerating it silently.
func TestNewEngine_MFAGateWithoutAccountValidatorFailsConstruction(t *testing.T) {
	engine, err := NewEngine([]byte(lifecycleTestSecret),
		WithMFAGate(lifecycleGate{enrolled: true}),
		WithMinter(&lifecycleMinter{}),
	)
	require.Error(t, err, "an MFA-gated engine without an AccountValidator must fail construction")
	assert.Nil(t, engine)
	assert.ErrorContains(t, err, "WithMFAGate")
	assert.ErrorContains(t, err, "WithAccountValidator")
	assert.ErrorIs(t, err, ErrMissingAccountValidator)
}

// TestNewEngine_MFAGateWithAccountValidatorConstructs proves the guard is a wiring
// requirement, not a ban: the documented wiring (gate + validator) constructs cleanly.
func TestNewEngine_MFAGateWithAccountValidatorConstructs(t *testing.T) {
	engine, err := NewEngine([]byte(lifecycleTestSecret),
		WithMFAGate(lifecycleGate{enrolled: true}),
		WithMinter(&lifecycleMinter{}),
		WithAccountValidator(&lifecycleValidator{}),
	)
	require.NoError(t, err)
	require.NotNil(t, engine)
}

// TestNewEngine_WithoutMFAGate_ValidatorStaysOptional proves the guard's blast radius is
// exactly the MFA-gated engines: without a MFAGate there is no step-up path to re-check,
// so a validator is not required (no gate and no validator is the minimal valid engine).
func TestNewEngine_WithoutMFAGate_ValidatorStaysOptional(t *testing.T) {
	engine, err := NewEngine([]byte(lifecycleTestSecret))
	require.NoError(t, err)
	require.NotNil(t, engine)

	engine, err = NewEngine([]byte(lifecycleTestSecret), WithMinter(&lifecycleMinter{}))
	require.NoError(t, err)
	require.NotNil(t, engine)
}

// TestProcessStepUp_DisabledAfterChallengeIsRefused proves the acceptance criterion: an
// account administratively disabled AFTER the challenge was issued must not be able to
// complete the in-flight flow — step-up is refused and no credentials are minted.
func TestProcessStepUp_DisabledAfterChallengeIsRefused(t *testing.T) {
	validator := &lifecycleValidator{}
	minter := &lifecycleMinter{}
	engine, err := NewEngine([]byte(lifecycleTestSecret),
		WithMFAGate(lifecycleGate{enrolled: true}),
		WithMinter(minter),
		WithAccountValidator(validator),
	)
	require.NoError(t, err)

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := lifecycleChallenge(t, engine, user)

	// The account is disabled mid-flow (during the ≤5 min flow-token window).
	validator.script = []error{identity.ErrAccountDisabled}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	_, err = engine.ProcessStepUp(context.Background(), rec, req, flowToken, "totp", []string{tokens.AMROTP})

	require.ErrorIs(t, err, identity.ErrAccountDisabled)
	assert.Empty(t, minter.minted, "a disabled account's in-flow step-up must not mint credentials")
}

// TestProcessStepUp_EnabledAccountCompletesAfterChallenge is the contrast half: the same
// wiring with an account that stays active completes the flow and mints exactly once.
func TestProcessStepUp_EnabledAccountCompletesAfterChallenge(t *testing.T) {
	minter := &lifecycleMinter{}
	engine, err := NewEngine([]byte(lifecycleTestSecret),
		WithMFAGate(lifecycleGate{enrolled: true}),
		WithMinter(minter),
		WithAccountValidator(&lifecycleValidator{}),
	)
	require.NoError(t, err)

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := lifecycleChallenge(t, engine, user)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	result, err := engine.ProcessStepUp(context.Background(), rec, req, flowToken, "totp", []string{tokens.AMROTP})

	require.NoError(t, err)
	require.Equal(t, StateCompleted, result.State)
	require.Len(t, minter.minted, 1)
}

// TestProcessStepUp_RefusedWhenValidatorMissingAtRequestTime proves the request-time
// defense in depth: an Engine that reached runtime without an AccountValidator — e.g.
// assembled as a struct literal, bypassing NewEngine's construction guard — must refuse
// the step-up instead of minting credentials unchecked.
func TestProcessStepUp_RefusedWhenValidatorMissingAtRequestTime(t *testing.T) {
	minter := &lifecycleMinter{}
	engine, err := NewEngine([]byte(lifecycleTestSecret),
		WithMFAGate(lifecycleGate{enrolled: true}),
		WithMinter(minter),
		WithAccountValidator(&lifecycleValidator{}),
	)
	require.NoError(t, err)

	user := &identity.User{ID: uuid.Must(uuid.NewV7()), TenantID: "tenant-1", Email: "u@example.com"}
	flowToken := lifecycleChallenge(t, engine, user)

	// Simulate an Engine built as a struct literal: the validator seam is missing.
	engine.validator = nil

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mfa/step-up", nil)
	_, err = engine.ProcessStepUp(context.Background(), rec, req, flowToken, "totp", []string{tokens.AMROTP})

	require.ErrorIs(t, err, ErrMissingAccountValidator)
	assert.Empty(t, minter.minted, "step-up must fail closed when the lifecycle re-check is unconfigured")
}
