// Package event defines egauth's optional security-event seam. Services emit lifecycle and
// security events — login success/failure, account lockout, refresh-token reuse, MFA changes,
// API-key lifecycle (creation, successful auth, failed auth), delivery failures,
// ... — to a Sink the application supplies. It is entirely optional (a nil Sink disables
// emission) and dependency-free, so any module can emit without coupling to a particular
// logging or telemetry implementation.
//
// A ready-made slog adapter (NewSlogSink) covers the common "just log it" case, giving the
// injectable *slog.Logger seam; richer consumers implement Sink to feed a SIEM, metrics pipeline,
// or an append-only audit table. Use MultiSink to fan out to several.
//
// Events are observability records, not a response channel: emitting (or not) never changes a
// handler's client-visible behavior, so emitting on a failed-login or unknown-account path is
// safe and does not create an enumeration oracle. For the same reason events carry a short
// machine Reason rather than secrets, tokens, passwords or raw attacker input.
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package event

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
)

// Type identifies a security or lifecycle event.
type Type string

// The event types egauth emits.
const (
	LoginSucceeded          Type = "login.succeeded"
	LoginFailed             Type = "login.failed"
	SessionIssued           Type = "session.issued" // a login flow minted a credential pair through the unified issuance pipeline; Attrs carry method, authn_methods, remember_me, must_change_password
	AccountLocked           Type = "account.locked"
	UserRegistered          Type = "user.registered"
	PasswordReset           Type = "password.reset"   // completed via a reset token
	PasswordChanged         Type = "password.changed" // authenticated self-service change
	EmailVerified           Type = "email.verified"
	EmailChanged            Type = "email.changed"
	PhoneVerified           Type = "phone.verified"
	RecoveryChannelEnrolled Type = "recovery_channel.enrolled"
	AccountDeleted          Type = "account.deleted"
	Logout                  Type = "logout"           // a session was revoked (sign-out, "log out everywhere")
	AccountBlocked          Type = "account.blocked"  // access denied by policy (rate limit, IP/geo, risk), distinct from account.locked
	AccountDisabled         Type = "account.disabled" // reversible administrative suspension
	AccountEnabled          Type = "account.enabled"  // administrative re-activation
	RefreshReuseDetected    Type = "refresh.reuse_detected"
	TokenFamilyRevoked      Type = "token.family_revoked"
	MFAChallengeRequired    Type = "mfa.challenge_required" // a login flow paused mid-pipeline: a second factor must be satisfied before final credential issuance (login flow)
	MFAVerified             Type = "mfa.verified"           // a second factor (TOTP or recovery code) was successfully verified
	MFAVerificationFailed   Type = "mfa.verification_failed"
	MFAUnlocked             Type = "mfa.unlocked"       // an operator reset a locked-out second factor (UnlockMFA)
	CredentialAdded         Type = "credential.added"   // a passkey/WebAuthn credential was registered
	CredentialRemoved       Type = "credential.removed" // a passkey/WebAuthn credential was deleted
	DeliveryFailed          Type = "delivery.failed"    // a swallowed mailer/delivery error (outage signal)

	// API-key lifecycle events.
	APIKeyCreated       Type = "api_key.created"        // a new API key (PAT or service token) was issued; carries type and created_by in Attrs
	APIKeyRevoked       Type = "api_key.revoked"        // an API key was administratively soft-revoked; carries type and created_by in Attrs (mirrors api_key.created; no secret)
	APIKeyAuthSucceeded Type = "api_key.auth.succeeded" // an API key was verified successfully; carries key type in Attrs
	APIKeyAuthFailed    Type = "api_key.auth.failed"    // an API key verification failed; Reason carries the failure code (see ReasonAPIKey* constants)
)

// Reason codes for APIKeyAuthFailed events. These are the only valid values for Event.Reason
// when Type is APIKeyAuthFailed. They are intentionally short machine codes: no secrets,
// tokens or raw attacker input.
const (
	ReasonAPIKeyNotFound       = "not_found"       // no key matched the provided token hash
	ReasonAPIKeyExpired        = "expired"         // the key exists but its expiry has passed
	ReasonAPIKeyRevoked        = "revoked"         // the key exists but has been administratively soft-revoked
	ReasonAPIKeyTenantMismatch = "tenant_mismatch" // the key belongs to a different tenant
	ReasonAPIKeyWrongType      = "wrong_type"      // the caller required a specific key type (PAT or service) but got the other
)

// Event is a single security-relevant occurrence.
type Event struct {
	// Type is the event kind (required).
	Type Type
	// TenantID and UserID scope the event when known ("" otherwise). UserID is a UUID string;
	// the package avoids importing uuid so any module can emit without coupling. UserID is
	// personal data, classified PII like the "created_by" attribute: NewSlogSink omits it and the
	// otel adapter exports it only when cleared for PII.
	TenantID string
	UserID   string
	// Reason is a short machine code for an outcome or failure (e.g. "invalid_credentials",
	// "account_locked", "reuse_after_grace"). Keep it free of secrets and raw user input.
	Reason string
	// Err describes the underlying failure of an outage event (e.g. a swallowed mailer or store
	// error), so an otherwise-invisible outage is observable. Its text may embed personal data (a
	// rejected mailbox, a phone number) and is classified PII: NewSlogSink logs only its type.
	Err Cause
	// Attrs carries extra structured context. Never put secrets, tokens or passwords here.
	Attrs map[string]any
}

// Cause is the failure behind an outage event, reduced to the dynamic type of the error and its
// text. It holds no error value, so a sink cannot unwrap, compare or format it into a log by
// accident. The text is classified PII.
type Cause struct {
	typeName string
	text     string
}

// CauseOf describes err; it returns the zero Cause for a nil error.
func CauseOf(err error) Cause {
	if err == nil {
		return Cause{}
	}
	return Cause{typeName: fmt.Sprintf("%T", err), text: err.Error()}
}

// IsZero reports whether c describes no failure.
func (c Cause) IsZero() bool { return c.typeName == "" }

// Type returns the dynamic Go type of the failure, such as "*net.OpError". It carries no personal data.
func (c Cause) Type() string { return c.typeName }

// Text returns the error text, which may embed personal data.
func (c Cause) Text() string { return c.text }

// String renders only the dynamic type, never the text, so fmt and log verbs cannot leak it.
func (c Cause) String() string {
	if c.IsZero() {
		return "<nil>"
	}
	return c.typeName
}

// GoString renders only the dynamic type, for the %#v verb.
func (c Cause) GoString() string { return c.String() }

// Format renders only the dynamic type for every fmt verb, including %+v.
func (c Cause) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue renders only the dynamic type for slog.
func (c Cause) LogValue() slog.Value { return slog.StringValue(c.String()) }

// Sink receives emitted events. Implementations MUST be safe for concurrent use and SHOULD NOT
// block the caller (buffer or dispatch asynchronously if the backend is slow).
type Sink interface {
	EmitEvent(ctx context.Context, e Event)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(ctx context.Context, e Event)

// EmitEvent implements Sink.
func (f SinkFunc) EmitEvent(ctx context.Context, e Event) { f(ctx, e) }

// Emit sends e to sink when sink is non-nil, so a nil (unconfigured) sink is a cheap no-op. It is
// meant for applications emitting their own events: library code emits through internal/audit,
// which enforces the attribute registry, and a guard test rejects any other library emitter. A
// panic in the sink is recovered and logged, so a misbehaving audit sink can never change a
// handler's client-visible behavior (the invariant this package documents); a blocking sink stays
// the implementation's responsibility, as the Sink contract requires non-blocking dispatch.
func Emit(ctx context.Context, sink Sink, e Event) {
	if sink != nil {
		safeEmit(ctx, sink, e)
	}
}

func safeEmit(ctx context.Context, sink Sink, e Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("egauth: event sink panicked", "event", string(e.Type), "panic", r)
		}
	}()
	sink.EmitEvent(ctx, e)
}

type multiSink []Sink

// MultiSink returns a Sink that fans every event out to each of sinks (nil entries are skipped).
// Members receive Event.Public(): PII, Secret and unregistered attributes (including "ip",
// "user_agent" and "previous_email") never reach them, so a member that needs PII must be
// installed directly instead of behind MultiSink.
func MultiSink(sinks ...Sink) Sink { return multiSink(sinks) }

func (m multiSink) EmitEvent(ctx context.Context, e Event) {
	e = e.Public()
	for _, s := range m {
		if s != nil {
			safeEmit(ctx, s, e)
		}
	}
}

type slogSink struct{ logger *slog.Logger }

// NewSlogSink returns a Sink that logs events to logger (slog.Default() when nil). An event
// carrying an Err is logged at Error; otherwise the level follows Type.Severity. Only public data
// is logged: Event.PublicAttrs, the tenant, the reason and the dynamic type of Err ("error_type").
// The user id and the error text are PII and are never logged.
func NewSlogSink(logger *slog.Logger) Sink {
	if logger == nil {
		logger = slog.Default()
	}
	return &slogSink{logger: logger}
}

func (s *slogSink) EmitEvent(ctx context.Context, e Event) {
	attrs := make([]slog.Attr, 0, 4+len(e.Attrs))
	attrs = append(attrs, slog.String("event", string(e.Type)))
	if e.TenantID != "" {
		attrs = append(attrs, slog.String("tenant_id", e.TenantID))
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	public := e.PublicAttrs()
	for _, k := range slices.Sorted(maps.Keys(public)) {
		attrs = append(attrs, slog.Any(k, public[k]))
	}
	if !e.Err.IsZero() {
		attrs = append(attrs, slog.String("error_type", e.Err.Type()))
	}
	s.logger.LogAttrs(ctx, levelFor(e), "egauth security event", attrs...)
}

func levelFor(e Event) slog.Level {
	if !e.Err.IsZero() {
		return slog.LevelError
	}
	switch e.Type.Severity() {
	case SeverityError:
		return slog.LevelError
	case SeverityWarn:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// DiscardSink drops every event, for deployments that disable emission explicitly instead of
// passing a nil Sink. It has a single, zero-size value, so Discard cannot be rebound to a sink
// that does anything else.
type DiscardSink struct{}

// EmitEvent implements Sink and does nothing.
func (DiscardSink) EmitEvent(context.Context, Event) {}

// Discard is the DiscardSink to pass when emission is disabled on purpose.
var Discard DiscardSink

// RequestContext carries optional client IP and User-Agent for an application that emits its own
// events. The library does not read it: its own events take the client from the request. Both
// fields may be empty; ApplyTo then adds nothing. It carries no secrets.
type RequestContext struct {
	// IP is the client IP address as the application observed it. It is not parsed or validated and
	// is recorded verbatim under the "ip" attribute when non-empty.
	IP string
	// UserAgent is the client's User-Agent string, recorded verbatim under the "user_agent"
	// attribute when non-empty.
	UserAgent string
}

// Attr keys used by RequestContext.ApplyTo.
const (
	AttrIP        = "ip"
	AttrUserAgent = "user_agent"
)

// Attr keys describing a change to the account's contact or recovery surface. They exist so a
// consumer's sink can alert the address that LOST access, not only report the new state: changing
// the account email or adding a recovery channel needs only a live session, so the outgoing
// address is often the only party still able to notice and object. The values are contact
// identifiers, never credentials — a token or code is never carried on an event. They are
// classified PII: MultiSink, NewSlogSink and the default otel sink drop them, so the alerting
// sink must be installed directly and read Event.AttrsUpTo(PII).
const (
	// AttrPreviousEmail is the account email before an EmailChanged event.
	AttrPreviousEmail = "previous_email"
	// AttrNewEmail is the account email after an EmailChanged event.
	AttrNewEmail = "new_email"
	// AttrRecoveryChannel is the address or number added by a RecoveryChannelEnrolled or
	// PhoneVerified event.
	AttrRecoveryChannel = "recovery_channel"
)

// RequestContextFrom collapses a variadic RequestContext option into a single value. Auth entry
// points accept the context as a trailing variadic argument so it is optional and existing callers
// keep compiling; this helper gives them one uniform way to interpret it. When several are passed
// the last one wins (so a wrapper can supply a default that an inner call overrides); when none are
// passed the zero RequestContext is returned (both fields empty), which contributes no Attrs.
func RequestContextFrom(opts ...RequestContext) RequestContext {
	if len(opts) == 0 {
		return RequestContext{}
	}
	return opts[len(opts)-1]
}

// ApplyTo copies rc's non-empty fields into attrs under the AttrIP / AttrUserAgent keys and
// returns the (possibly newly allocated) map. A nil attrs is allocated only when rc has at least
// one non-empty field, so a zero RequestContext applied to a nil map returns nil and adds nothing —
// the emit site then carries no IP/User-Agent attribute. Existing entries in attrs are preserved;
// only the IP/User-Agent keys are set.
func (rc RequestContext) ApplyTo(attrs map[string]any) map[string]any {
	if rc.IP == "" && rc.UserAgent == "" {
		return attrs
	}
	if attrs == nil {
		attrs = make(map[string]any, 2)
	}
	if rc.IP != "" {
		attrs[AttrIP] = rc.IP
	}
	if rc.UserAgent != "" {
		attrs[AttrUserAgent] = rc.UserAgent
	}
	return attrs
}
