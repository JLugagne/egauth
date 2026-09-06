package authflow

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/identity"
)

// FlowState identifies the current stage in the authentication flow pipeline.
type FlowState string

const (
	StateInitial       FlowState = "initial"
	StateMFAChallenged FlowState = "mfa_challenged"
	StateCompleted     FlowState = "completed"
	StateRejected      FlowState = "rejected"
)

var (
	// ErrInvalidFlowToken is returned when a flow token is malformed, has an invalid signature,
	// or cannot be decoded.
	ErrInvalidFlowToken = errors.New("invalid or tampered flow token")

	// ErrFlowTokenExpired is returned when a flow token has passed its expiration deadline.
	ErrFlowTokenExpired = errors.New("flow token has expired")

	// ErrInvalidFlowState is returned when an operation is attempted from an incompatible state.
	ErrInvalidFlowState = errors.New("invalid flow state for operation")

	// ErrMFARequired is returned or flagged when MFA is mandatory before final session issuance.
	ErrMFARequired = errors.New("mfa verification required")
)

// FlowContext holds the accumulated state and assurance metadata of an authentication ceremony.
type FlowContext struct {
	FlowID             string         `json:"flow_id"`
	TenantID           string         `json:"tenant_id"`
	UserID             uuid.UUID      `json:"user_id"`
	UserEmail          string         `json:"user_email,omitempty"`
	State              FlowState      `json:"state"`
	PrimaryFactor      string         `json:"primary_factor"`
	Factors            []string       `json:"factors"`
	AMR                []string       `json:"amr"`
	MustChangePassword bool           `json:"must_change_password,omitempty"`
	RememberMe         bool           `json:"remember_me,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	ExpiresAt          time.Time      `json:"expires_at"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// FlowResult contains the outcome of an engine processing step.
type FlowResult struct {
	Flow      *FlowContext
	State     FlowState
	FlowToken string // Non-empty only when State == StateMFAChallenged
}

// AccountValidator validates account lifecycle conditions (e.g. active, not disabled, not deleted).
type AccountValidator interface {
	ValidateAccount(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// IdentityAccountValidator adapts an identity.UserStore to the AccountValidator interface.
type IdentityAccountValidator struct {
	store identity.UserStore
}

// NewIdentityAccountValidator wraps an identity.UserStore to validate account active status.
func NewIdentityAccountValidator(store identity.UserStore) *IdentityAccountValidator {
	return &IdentityAccountValidator{store: store}
}

// ValidateAccount checks if the user is suspended or deleted.
func (v *IdentityAccountValidator) ValidateAccount(ctx context.Context, tenantID string, userID uuid.UUID) error {
	user, err := v.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if user == nil || user.DeletedAt != nil || user.DisabledAt != nil {
		return identity.ErrAccountDisabled
	}
	return nil
}

// MFAGate queries whether MFA is enrolled/required for a user.
type MFAGate interface {
	IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

// PasswordPolicyChecker queries whether a user is subject to forced password change.
type PasswordPolicyChecker func(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)

// SessionMinter mints the final authenticated session or tokens upon successful flow completion.
type SessionMinter interface {
	Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *FlowContext) error
}
