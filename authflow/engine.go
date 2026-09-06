package authflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
)

const (
	DefaultTokenTTL       = 5 * time.Minute
	DefaultFlowCookieName = "auth_flow_token"
)

// Engine orchestrates the authentication state machine and credentials pipeline.
type Engine struct {
	secret     []byte
	ttl        time.Duration
	mfaGate    MFAGate
	minter     SessionMinter
	validator  AccountValidator
	pwChecker  PasswordPolicyChecker
	cookieName string
	sink       event.Sink
	now        func() time.Time
}

// Option configures an Engine instance.
type Option func(*Engine)

func WithMFAGate(gate MFAGate) Option {
	return func(e *Engine) { e.mfaGate = gate }
}

func WithMinter(minter SessionMinter) Option {
	return func(e *Engine) { e.minter = minter }
}

func WithAccountValidator(v AccountValidator) Option {
	return func(e *Engine) { e.validator = v }
}

func WithPasswordPolicyChecker(c PasswordPolicyChecker) Option {
	return func(e *Engine) { e.pwChecker = c }
}

func WithTokenTTL(ttl time.Duration) Option {
	return func(e *Engine) {
		if ttl > 0 {
			e.ttl = ttl
		}
	}
}

func WithCookieName(name string) Option {
	return func(e *Engine) { e.cookieName = name }
}

func WithEventSink(sink event.Sink) Option {
	return func(e *Engine) { e.sink = sink }
}

// NewEngine constructs a new authentication flow Engine.
func NewEngine(secret []byte, opts ...Option) (*Engine, error) {
	if len(secret) < 16 {
		return nil, errors.New("authflow: secret must be at least 16 bytes")
	}

	e := &Engine{
		secret:     secret,
		ttl:        DefaultTokenTTL,
		cookieName: DefaultFlowCookieName,
		now:        time.Now,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e, nil
}

// ProcessPrimaryAuth evaluates an in-flight primary authentication (password, magic link, oauth, passkey).
func (e *Engine) ProcessPrimaryAuth(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	user *identity.User,
	method string,
	initialAMR []string,
	remember bool,
) (*FlowResult, error) {
	if user == nil {
		return nil, identity.ErrUserNotFound
	}

	now := e.now()

	// 1. Account Lifecycle Check
	if user.DeletedAt != nil || user.DisabledAt != nil {
		e.emit(ctx, event.Event{
			Type:     event.LoginFailed,
			UserID:   user.ID.String(),
			TenantID: user.TenantID,
			Attrs:    map[string]any{"reason": "account_disabled", "method": method},
		})
		return nil, identity.ErrAccountDisabled
	}
	if e.validator != nil {
		if err := e.validator.ValidateAccount(ctx, user.TenantID, user.ID); err != nil {
			e.emit(ctx, event.Event{
				Type:     event.LoginFailed,
				UserID:   user.ID.String(),
				TenantID: user.TenantID,
				Attrs:    map[string]any{"reason": "account_validation_failed", "method": method},
			})
			return nil, err
		}
	}

	// 2. Forced password change check
	mustChange := false
	if e.pwChecker != nil {
		var err error
		mustChange, err = e.pwChecker(ctx, user.TenantID, user.ID)
		if err != nil {
			return nil, fmt.Errorf("password policy check: %w", err)
		}
	}

	flow := &FlowContext{
		FlowID:             uuid.New().String(),
		TenantID:           user.TenantID,
		UserID:             user.ID,
		UserEmail:          user.Email,
		State:              StateInitial,
		PrimaryFactor:      method,
		Factors:            []string{method},
		AMR:                append([]string{}, initialAMR...),
		MustChangePassword: mustChange,
		RememberMe:         remember,
		CreatedAt:          now,
		ExpiresAt:          now.Add(e.ttl),
	}

	// 3. MFA Policy Enforcement
	mfaRequired := false
	if e.mfaGate != nil {
		enrolled, err := e.mfaGate.IsEnrolled(ctx, user.TenantID, user.ID)
		if err != nil {
			return nil, fmt.Errorf("mfa check: %w", err)
		}
		mfaRequired = enrolled
	}

	if mfaRequired {
		flow.State = StateMFAChallenged
		flowToken, err := encodeFlowToken(flow, e.secret)
		if err != nil {
			return nil, err
		}

		if e.cookieName != "" && w != nil {
			http.SetCookie(w, &http.Cookie{
				Name:     e.cookieName,
				Value:    flowToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   r != nil && r.TLS != nil,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(e.ttl.Seconds()),
			})
		}

		e.emit(ctx, event.Event{
			Type:     event.MFAChallengeRequired,
			UserID:   user.ID.String(),
			TenantID: user.TenantID,
			Attrs:    map[string]any{"method": method, "flow_id": flow.FlowID},
		})

		return &FlowResult{
			Flow:      flow,
			State:     StateMFAChallenged,
			FlowToken: flowToken,
		}, nil
	}

	// 4. Flow Completed (No MFA required)
	flow.State = StateCompleted
	if e.minter != nil {
		if err := e.minter.Mint(ctx, w, r, flow); err != nil {
			return nil, fmt.Errorf("mint session: %w", err)
		}
	}

	e.clearFlowCookie(w, r)
	e.emit(ctx, event.Event{
		Type:     event.LoginSucceeded,
		UserID:   user.ID.String(),
		TenantID: user.TenantID,
		Attrs:    map[string]any{"method": method, "amr": flow.AMR},
	})

	return &FlowResult{
		Flow:  flow,
		State: StateCompleted,
	}, nil
}

// ProcessStepUp handles completion of a second-factor challenge using a flow token.
func (e *Engine) ProcessStepUp(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	flowToken string,
	factor string,
	factorAMR []string,
) (*FlowResult, error) {
	now := e.now()
	flow, err := decodeFlowToken(flowToken, e.secret, now)
	if err != nil {
		return nil, err
	}

	if flow.State != StateMFAChallenged {
		return nil, ErrInvalidFlowState
	}

	// Re-verify account lifecycle
	if e.validator != nil {
		if err := e.validator.ValidateAccount(ctx, flow.TenantID, flow.UserID); err != nil {
			return nil, err
		}
	}

	// Append factor and AMR
	flow.Factors = append(flow.Factors, factor)
	for _, a := range factorAMR {
		if !contains(flow.AMR, a) {
			flow.AMR = append(flow.AMR, a)
		}
	}
	if !contains(flow.AMR, tokens.AMRMFA) {
		flow.AMR = append(flow.AMR, tokens.AMRMFA)
	}

	flow.State = StateCompleted

	if e.minter != nil {
		if err := e.minter.Mint(ctx, w, r, flow); err != nil {
			return nil, fmt.Errorf("mint session: %w", err)
		}
	}

	e.clearFlowCookie(w, r)
	e.emit(ctx, event.Event{
		Type:     event.LoginSucceeded,
		UserID:   flow.UserID.String(),
		TenantID: flow.TenantID,
		Attrs:    map[string]any{"factors": flow.Factors, "amr": flow.AMR},
	})

	return &FlowResult{
		Flow:  flow,
		State: StateCompleted,
	}, nil
}

// ExtractFlowToken reads the flow token from the request header or cookie.
func (e *Engine) ExtractFlowToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if h := r.Header.Get("X-Auth-Flow-Token"); h != "" {
		return h
	}
	if e.cookieName != "" {
		if c, err := r.Cookie(e.cookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func (e *Engine) clearFlowCookie(w http.ResponseWriter, r *http.Request) {
	if w != nil && e.cookieName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     e.cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r != nil && r.TLS != nil,
			MaxAge:   -1,
		})
	}
}

func (e *Engine) emit(ctx context.Context, ev event.Event) {
	if e.sink != nil {
		e.sink.EmitEvent(ctx, ev)
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
