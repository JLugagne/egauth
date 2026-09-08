package authflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
)

const (
	DefaultTokenTTL = 5 * time.Minute

	// DefaultFlowCookieName is the secure-by-default name of the HTTP-only cookie that
	// carries the HMAC-sealed MFA step-up flow token (tenant/user/state). It carries the
	// browser-enforced __Host- prefix, which guarantees the cookie is host-locked: browsers
	// refuse to store it unless it is Secure, carries no Domain, and has Path=/. That
	// structurally defeats sibling-subdomain cookie-tossing — an attacker controlling
	// evil.example.com could otherwise plant their own legitimately-obtained flow cookie in
	// a victim's browser and drive the victim's second factor against the attacker's
	// account. Use WithCookieName to override it only when the deployment genuinely cannot
	// meet the __Host- requirements (plain-HTTP local development, a path-scoped mount);
	// overriding to a plain name forfeits the host-lock hardening.

	// hostPrefix is the browser-enforced __Host- cookie-name prefix (see
	// DefaultFlowCookieName and validate).
	hostPrefix = "__Host-"

	DefaultFlowCookieName = hostPrefix + "auth_flow_token"
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
	// cookieDomain and cookiePath are the attributes the flow-cookie set/clear sites write. There are deliberately no options to change them: the default __Host- name is only storable with an empty Domain and Path="/", and validate fails construction if that invariant is ever broken (e.g. by adding attribute options without extending the guard).
	cookieDomain string
	cookiePath   string
	sink         event.Sink
	now          func() time.Time
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

// WithCookieName overrides the name of the HTTP-only cookie that carries the MFA step-up
// flow token. The secure default is DefaultFlowCookieName ("__Host-auth_flow_token"), whose
// __Host- prefix makes browsers enforce the host-lock (Secure, no Domain, Path=/) that
// defeats sibling-subdomain cookie-tossing of the sealed flow state. Use it only as an
// escape hatch when the deployment genuinely cannot satisfy the __Host- requirements (e.g.
// a path-scoped cookie mount, or local plain-HTTP development); overriding to a plain name
// forfeits that hardening, and the trade-off is the caller's explicit choice. An empty name
// disables the flow cookie entirely (the flow token must then be carried by other means).
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
		cookiePath: "/",
		now:        time.Now,
	}

	for _, opt := range opts {
		opt(e)
	}

	// Fail construction loudly on a cookie configuration browsers would silently refuse to
	// store: a __Host- flow cookie that never reaches the browser breaks MFA step-up with
	// no visible cause.
	if err := e.validate(); err != nil {
		return nil, err
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
				Domain:   e.cookieDomain,
				Path:     e.cookiePath,
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
			Domain:   e.cookieDomain,
			Path:     e.cookiePath,
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

// validate fails construction when the flow-cookie name and the attributes the engine writes
// are incompatible. The __Host- prefix is browser-enforced: a cookie named __Host-* is
// silently discarded unless it is written with no Domain and Path=/ — the cookie would then
// never reach the browser and MFA step-up would fail with no visible cause, so the
// misconfiguration must be caught here, loudly, before the engine serves a single request.
// (The Secure attribute is request-driven; it is the deployment's job, not this guard's.)
func (e *Engine) validate() error {
	if !strings.HasPrefix(e.cookieName, hostPrefix) {
		return nil
	}
	var errs []error
	if e.cookieDomain != "" {
		errs = append(errs, fmt.Errorf("authflow: flow cookie %q: __Host- prefix requires Domain to be empty, got %q", e.cookieName, e.cookieDomain))
	}
	if e.cookiePath != "/" {
		errs = append(errs, fmt.Errorf("authflow: flow cookie %q: __Host- prefix requires Path=\"/\", got %q", e.cookieName, e.cookiePath))
	}
	return errors.Join(errs...)
}
