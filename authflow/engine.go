package authflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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
	// insecureCookies drops the Secure attribute on the flow cookie (WithInsecureCookies opt-out, local HTTP dev only). __Host- prefixed names always stay Secure regardless.
	insecureCookies bool
	// insecureWarnedOnce guards the one-shot InsecureCookieMisuse emission (see warnIfInsecureMisuse).
	insecureWarnedOnce *sync.Once
	sink               event.Sink
	now                func() time.Time
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

// WithInsecureCookies disables the Secure attribute on the flow cookie this engine writes and
// clears. Use only for local HTTP development: the default is Secure regardless of r.TLS, so a
// TLS-terminating reverse proxy forwarding plaintext no longer silently drops the attribute
// (browsers refuse __Host- cookies without Secure, which would break the MFA challenge
// round-trip) and a custom non-__Host- flow-cookie name would carry the bearer flow token on
// any plaintext request.
//
// The escape hatch is bounded: when the cookie name carries the browser-enforced __Host-
// prefix, Secure is ALWAYS kept (the tokens.Cookies.Validate() contract — Insecure may only
// apply to non-__Host- names).
//
// Misuse guard: when insecure cookies are served over a plaintext connection to a non-loopback
// host, the engine emits a one-shot event.InsecureCookieMisuse on its event sink (the same
// signal the tokens handlers emit), so a dev-only opt-out that leaked into a production-like
// deployment is observable. A nil sink makes the warning a no-op.
func WithInsecureCookies() Option {
	return func(e *Engine) { e.insecureCookies = true }
}

// WithCookieName overrides the flow-token cookie name.
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
		secret:             secret,
		ttl:                DefaultTokenTTL,
		cookieName:         DefaultFlowCookieName,
		now:                time.Now,
		insecureWarnedOnce: &sync.Once{},
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
	e.warnIfInsecureMisuse(ctx, r)
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
				Secure:   e.secureCookie(),
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
	e.warnIfInsecureMisuse(ctx, r)
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
			Secure:   e.secureCookie(),
			MaxAge:   -1,
		})
	}
}

// hostCookiePrefix is the browser-enforced cookie name prefix that requires Secure, no Domain,
// and Path=/ (the same contract as tokens' hostPrefix).
const hostCookiePrefix = "__Host-"

// isHostPrefixedCookieName reports whether name carries the browser-enforced __Host- prefix.
func isHostPrefixedCookieName(name string) bool {
	return strings.HasPrefix(name, hostCookiePrefix)
}

// secureCookie reports whether the cookies this engine writes must carry the Secure attribute.
// Secure is on by default — the WithInsecureCookies opt-out can only drop it for names WITHOUT
// the browser-enforced __Host- prefix, for which Secure is browser-mandatory and therefore
// always kept (the tokens.Cookies.Validate() contract).
func (e *Engine) secureCookie() bool {
	return !e.insecureCookies || isHostPrefixedCookieName(e.cookieName)
}

// warnIfInsecureMisuse emits a one-shot WARN event when the engine is configured with insecure
// (non-Secure) cookies yet is serving a request that looks like production: a non-loopback Host
// over a plaintext (non-TLS) connection. It mirrors the tokens handler-level guard: a legitimate
// reverse proxy that terminates TLS and forwards plaintext presents a non-loopback Host with
// r.TLS == nil, so it deliberately warns rather than refusing (refusing would brick that setup).
// The warning fires at most once per engine instance (sync.Once); with no event sink configured
// it is a no-op.
func (e *Engine) warnIfInsecureMisuse(ctx context.Context, r *http.Request) {
	if !e.insecureCookies || r == nil || r.TLS != nil || isLoopbackHost(r.Host) {
		return
	}
	once := e.insecureWarnedOnce
	if once == nil {
		// Defensive: an Engine built without NewEngine still must not panic; emit every time
		// rather than crash (the supported path always has a non-nil Once).
		once = &sync.Once{}
	}
	once.Do(func() {
		e.emit(ctx, event.Event{
			Type:   event.InsecureCookieMisuse,
			Reason: "non_loopback_plaintext_host",
			Attrs:  map[string]any{"host": r.Host},
		})
	})
}

// isLoopbackHost reports whether host (an HTTP Host header value, optionally with a port) refers
// to the local machine — localhost or a loopback IP literal. These are the legitimate local-HTTP
// development targets for WithInsecureCookies, so they must never trigger the misuse warning.
func isLoopbackHost(host string) bool {
	if host == "" {
		// No Host at all is not a host we can call "production"; stay quiet.
		return true
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
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
