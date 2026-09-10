package issuance

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// DefaultInterimTTL is the lifetime of the short-lived interim access token issued when an
// MFA-enrolled user has passed the primary factor but not yet the second factor. It is long
// enough to complete the step-up ceremony and too short to be a usable session.
const DefaultInterimTTL = 5 * time.Minute

// State is the authoritative account snapshot the pipeline re-loads before it mints a
// credential pair. A zero UserID means "not reported" and is only used for the identity check;
// TenantID, Disabled, Deleted and MustChangePassword are always authoritative.
type State struct {
	UserID             uuid.UUID
	TenantID           string
	Disabled           bool
	Deleted            bool
	MustChangePassword bool
}

// Resolver re-loads the authoritative account state for (tenantID, userID) at issuance time.
// It MUST answer from the system of record, not from a caller-supplied request snapshot, so an
// account disabled, deleted or recently flagged between credential verification and issuance is
// still caught. An unknown/deleted account is reported either as a State with Deleted set or as
// an error; both fail issuance.
type Resolver interface {
	ResolveSessionState(ctx context.Context, tenantID string, userID uuid.UUID) (State, error)
}

// ResolverFunc adapts a plain function to Resolver.
type ResolverFunc func(ctx context.Context, tenantID string, userID uuid.UUID) (State, error)

// ResolveSessionState implements Resolver.
func (f ResolverFunc) ResolveSessionState(ctx context.Context, tenantID string, userID uuid.UUID) (State, error) {
	return f(ctx, tenantID, userID)
}

// MFAGate reports whether a user has a confirmed second factor enrolled. mfa.Service satisfies
// it structurally, mirroring the identity.MFAEnrollmentChecker seam.
type MFAGate interface {
	IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error)
}

// Option configures a Pipeline.
type Option func(*config)

type config struct {
	resolver   Resolver
	mfaGate    MFAGate
	interimTTL time.Duration
	sink       event.Sink
	now        func() time.Time
}

// WithResolver configures the authoritative account-state resolver. It is required: it is also
// the account-lifecycle validator that makes WithMFAGate safe.
func WithResolver(r Resolver) Option {
	return func(c *config) { c.resolver = r }
}

// WithMFAGate configures the MFA gate applied once per issuance: when the resolved user is
// enrolled and the request has not already verified a second factor, the pipeline mints only a
// short-lived interim access token instead of a full, refreshable pair. Configuring a gate
// without an authoritative resolver fails construction with ErrMFAWithoutValidator.
func WithMFAGate(g MFAGate) Option {
	return func(c *config) { c.mfaGate = g }
}

// WithInterimTTL overrides the interim access-token lifetime (default DefaultInterimTTL). A
// non-positive value selects the default.
func WithInterimTTL(d time.Duration) Option {
	return func(c *config) { c.interimTTL = d }
}

// WithEventSink registers the sink that receives the pipeline's SessionIssued events. A nil
// sink (the default) disables emission.
func WithEventSink(s event.Sink) Option {
	return func(c *config) { c.sink = s }
}

// WithClock overrides the time source used for interim expiries (primarily for tests). A nil
// clock selects time.Now.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// Request describes one credential issuance. Claims is the base claims produced by the
// configured claims builder for the account; the pipeline overwrites the authoritative fields
// (subject, tenant, must-change) before minting.
type Request[C any] struct {
	// TenantID and UserID are the resolved request identity. The pipeline fails closed when the
	// authoritative state disagrees with either.
	TenantID string
	UserID   uuid.UUID
	// Claims carries the claims built for the account (scopes, roles, custom data, ...).
	Claims tokens.Claims[C]
	// Method is the audit label of the flow that authenticated the user (e.g. "password",
	// "magic_link", "oauth:google", "mfa_step_up").
	Method string
	// AMR lists the authentication methods the ceremony has actually verified. When non-nil it
	// replaces the base claims' AMR; when nil the base claims' AMR is preserved.
	AMR []string
	// MustChangePassword is the caller's authoritative forced-change signal for the credential it
	// verified (e.g. from Service.PasswordChangeRequired). The pipeline ORs it with the state's
	// flag, so a caller can add the flag but never clear it.
	MustChangePassword bool
	// MFAVerified marks a request that already completed a second factor (e.g. an MFA step-up).
	// The pipeline does not park such a request: the MFA gate is skipped and the full pair is
	// issued.
	MFAVerified bool
	// InterimTTL overrides the interim token lifetime for this request. Zero selects the
	// pipeline default.
	InterimTTL time.Duration
}

// Result is the outcome of a successful issuance.
type Result[C any] struct {
	// Pair is the minted access/refresh pair. For an interim issuance the refresh token is
	// minted but deliberately NOT delivered to the client by the caller (only the access cookie
	// is written), so the pre-step-up state is not a renewable session.
	Pair *tokens.TokenPair[C]
	// State is the authoritative state that was enforced.
	State State
	// Interim reports whether only the access token may be handed to the client.
	Interim bool
	// MustChangePassword is the effective flag stamped onto the pair.
	MustChangePassword bool
}

// Pipeline mints every interactive credential pair after enforcing the post-authentication
// invariants. It is safe for concurrent use.
type Pipeline[C any] struct {
	issuer   tokens.Issuer[C]
	resolver Resolver
	gate     MFAGate
	interim  time.Duration
	sink     event.Sink
	now      func() time.Time
}

// New builds an issuance pipeline. It fails construction when there is no issuer, when no
// authoritative resolver is configured, or when an MFA gate is configured without that resolver
// (ErrMFAWithoutValidator) — a gate whose account check could be skipped must never reach
// runtime.
func New[C any](issuer tokens.Issuer[C], opts ...Option) (*Pipeline[C], error) {
	cfg := config{now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	if cfg.mfaGate != nil && cfg.resolver == nil {
		return nil, ErrMFAWithoutValidator
	}
	if cfg.resolver == nil {
		return nil, ErrMissingResolver
	}
	if cfg.interimTTL <= 0 {
		cfg.interimTTL = DefaultInterimTTL
	}
	return &Pipeline[C]{
		issuer:   issuer,
		resolver: cfg.resolver,
		gate:     cfg.mfaGate,
		interim:  cfg.interimTTL,
		sink:     cfg.sink,
		now:      cfg.now,
	}, nil
}

// Issue re-loads the authoritative account state, applies the post-authentication invariants
// and mints the credential pair through the configured issuer. It is the only library-owned
// entry point for login-time issuance.
func (p *Pipeline[C]) Issue(ctx context.Context, req Request[C]) (*Result[C], error) {
	state, err := p.resolver.ResolveSessionState(ctx, req.TenantID, req.UserID)
	if err != nil {
		return nil, err
	}
	if state.UserID != uuid.Nil && state.UserID != req.UserID {
		return nil, ErrUserMismatch
	}
	// Tenant binding is fail-closed: a resolver that answers with a different partition (or a
	// caller that threaded the wrong tenant) must never mint a session into it, and an empty
	// state tenant must not be silently accepted when the request carried a real one.
	if state.TenantID != req.TenantID {
		return nil, ErrTenantMismatch
	}
	if state.Deleted {
		return nil, ErrAccountDeleted
	}
	if state.Disabled {
		return nil, ErrAccountDisabled
	}

	mustChange := req.MustChangePassword || state.MustChangePassword

	claims := req.Claims
	claims.Subject = req.UserID
	claims.TenantID = state.TenantID
	claims.MustChangePassword = mustChange
	if req.AMR != nil {
		claims.AMR = append([]string(nil), req.AMR...)
	}

	interim := false
	if p.gate != nil && !req.MFAVerified {
		enrolled, err := p.gate.IsEnrolled(ctx, state.TenantID, req.UserID)
		if err != nil {
			return nil, err
		}
		if enrolled {
			interim = true
			ttl := req.InterimTTL
			if ttl <= 0 {
				ttl = p.interim
			}
			claims.ExpiresAt = p.now().Add(ttl)
		}
	}

	pair, err := p.issuer.IssueTokenPair(ctx, claims)
	if err != nil {
		return nil, err
	}

	event.Emit(ctx, p.sink, event.Event{
		Type:     event.SessionIssued,
		UserID:   req.UserID.String(),
		TenantID: state.TenantID,
		Attrs: map[string]any{
			"method":               req.Method,
			"amr":                  pair.Claims.AMR,
			"interim":              interim,
			"must_change_password": mustChange,
		},
	})

	return &Result[C]{
		Pair:               pair,
		State:              state,
		Interim:            interim,
		MustChangePassword: mustChange,
	}, nil
}
