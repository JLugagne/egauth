package authflow

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// FactorVerifier verifies second-factor codes against the user bound to a challenged flow.
// mfa.Service satisfies this interface structurally, so the mfa module can be plugged in
// without authflow importing it (mirroring the identity.MFAEnrollmentChecker seam convention).
type FactorVerifier interface {
	VerifyTOTP(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
	VerifyRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, code string) error
}

// HandlerFlow adapts an Engine to the single-method auth-flow seams defined by the handler
// packages (identity.AuthFlow and oauth.AuthFlow — both structurally identical). The FlowResult
// is dropped: by the time ProcessPrimaryAuth returns, the engine has already written everything
// the client needs to w — either the final credentials (StateCompleted, via the SessionMinter)
// or the flow-token cookie (StateMFAChallenged). A non-nil error means the flow was rejected
// (disabled account, policy failure, mint failure) and no credentials were written.
type HandlerFlow struct {
	engine *Engine
}

// NewHandlerFlow wraps an Engine for use with identity.WithAuthFlow / oauth.WithAuthFlow.
func NewHandlerFlow(e *Engine) *HandlerFlow {
	return &HandlerFlow{engine: e}
}

// ProcessPrimaryAuth implements the handler-package seam by delegating to the engine.
func (h *HandlerFlow) ProcessPrimaryAuth(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	user *identity.User,
	method string,
	initialAMR []string,
	remember bool,
) error {
	_, err := h.engine.ProcessPrimaryAuth(ctx, w, r, user, method, initialAMR, remember)
	return err
}

// DecodeFlowToken validates the signature and expiry of a flow token and returns its context
// without mutating any state. Handlers use it to inspect a challenged ceremony (e.g. to scope
// a second-factor verification to the right tenant/user) before calling ProcessStepUp.
func (e *Engine) DecodeFlowToken(tokenStr string) (*FlowContext, error) {
	if tokenStr == "" {
		return nil, ErrInvalidFlowToken
	}
	return decodeFlowToken(tokenStr, e.secret, e.now())
}

const (
	// DefaultStepUpCodeField is the form field carrying the second-factor code.
	DefaultStepUpCodeField = "code"
	// DefaultStepUpMaxBodyBytes bounds the step-up request body (a TOTP or recovery code is tiny).
	DefaultStepUpMaxBodyBytes = int64(4 * 1024)

	factorTOTP     = "totp"
	factorRecovery = "recovery_code"
)

type stepUpConfig struct {
	codeField    string
	maxBodyBytes int64
	successURL   string
	failureURL   string
}

// StepUpOption configures StepUpHandler.
type StepUpOption func(*stepUpConfig)

// WithStepUpCodeField sets the form field carrying the TOTP / recovery code (default "code").
func WithStepUpCodeField(name string) StepUpOption {
	return func(c *stepUpConfig) {
		if name != "" {
			c.codeField = name
		}
	}
}

// WithStepUpMaxBodyBytes bounds the step-up request body size (default 4 KiB).
func WithStepUpMaxBodyBytes(n int64) StepUpOption {
	return func(c *stepUpConfig) {
		if n > 0 {
			c.maxBodyBytes = n
		}
	}
}

// WithStepUpSuccessRedirect sets the redirect target after a completed step-up
// (default: 204 No Content).
func WithStepUpSuccessRedirect(rawURL string) StepUpOption {
	return func(c *stepUpConfig) { c.successURL = rawURL }
}

// WithStepUpFailureRedirect sets the redirect target for a rejected step-up. When empty,
// failures render as a JSON error body with the appropriate status code.
func WithStepUpFailureRedirect(rawURL string) StepUpOption {
	return func(c *stepUpConfig) { c.failureURL = rawURL }
}

// StepUpHandler builds the HTTP completion endpoint of the FlowToken protocol: the second half
// of the ceremony that ProcessPrimaryAuth parks in StateMFAChallenged. It reads the flow token
// (cookie or X-Auth-Flow-Token header via Engine.ExtractFlowToken), decodes it to scope the
// verification to the challenged tenant/user, verifies the submitted code with the
// FactorVerifier (TOTP first, single-use recovery code as fallback — the same order
// mfa.StepUpHandler applies in the interim-token model), and on success completes the flow via
// Engine.ProcessStepUp: the SessionMinter issues the final credentials with the accumulated AMR
// and the flow cookie is cleared.
//
// Every rejection path answers a uniform 401 so the endpoint does not leak whether a flow token
// was expired, tampered, or the code was simply wrong. The flow token itself is stateless; its
// replay window is bounded by the engine TTL and, more importantly, a replay still requires a
// valid second-factor code (TOTP steps are single-use via the mfa store, recovery codes are
// consumed on use).
func StepUpHandler(e *Engine, v FactorVerifier, opts ...StepUpOption) http.HandlerFunc {
	cfg := stepUpConfig{
		codeField:    DefaultStepUpCodeField,
		maxBodyBytes: DefaultStepUpMaxBodyBytes,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	fail := func(w http.ResponseWriter, r *http.Request, status int, code string) {
		httputil.Fail(w, r, cfg.failureURL, status, code)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		flowToken := e.ExtractFlowToken(r)
		flow, err := e.DecodeFlowToken(flowToken)
		if err != nil {
			fail(w, r, http.StatusUnauthorized, "invalid_flow_token")
			return
		}

		if !httputil.ParseLimitedForm(w, r, cfg.maxBodyBytes, fail) {
			return
		}
		code := r.PostForm.Get(cfg.codeField)
		if code == "" {
			fail(w, r, http.StatusUnauthorized, "mfa_verification_failed")
			return
		}

		factor := factorTOTP
		if verr := v.VerifyTOTP(r.Context(), flow.TenantID, flow.UserID, code); verr != nil {
			if rerr := v.VerifyRecoveryCode(r.Context(), flow.TenantID, flow.UserID, code); rerr != nil {
				fail(w, r, http.StatusUnauthorized, "mfa_verification_failed")
				return
			}
			factor = factorRecovery
		}

		if _, err := e.ProcessStepUp(r.Context(), w, r, flowToken, factor, []string{tokens.AMROTP}); err != nil {
			switch {
			case errors.Is(err, ErrInvalidFlowToken),
				errors.Is(err, ErrFlowTokenExpired),
				errors.Is(err, ErrInvalidFlowState),
				errors.Is(err, identity.ErrAccountDisabled):
				fail(w, r, http.StatusUnauthorized, "invalid_flow_token")
			default:
				fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
			}
			return
		}

		httputil.RedirectOrStatus(w, r, cfg.successURL, http.StatusNoContent)
	}
}
