// Package event defines egauth's optional security-event seam. Services emit lifecycle and
// security events — login success/failure, account lockout, refresh-token reuse, MFA changes,
// API-key lifecycle (creation, successful auth, failed auth, expiry purge), delivery failures,
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
package event

import (
	"context"
	"log/slog"
)

// Type identifies a security or lifecycle event.
type Type string

// The event types egauth emits.
const (
	LoginSucceeded          Type = "login.succeeded"
	LoginFailed             Type = "login.failed"
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
	MFAEnrolled             Type = "mfa.enrolled"
	MFAConfirmed            Type = "mfa.confirmed"
	MFAVerificationFailed   Type = "mfa.verification_failed"
	MFADisabled             Type = "mfa.disabled"
	DeliveryFailed          Type = "delivery.failed"         // a swallowed mailer/delivery error (outage signal)
	InsecureCookieMisuse    Type = "cookies.insecure_misuse" // Insecure (non-Secure) cookies served to a non-loopback, non-TLS host (likely production misconfiguration)

	// API-key lifecycle events.
	APIKeyCreated       Type = "api_key.created"        // a new API key (PAT or service token) was issued; carries type and created_by in Attrs
	APIKeyRevoked       Type = "api_key.revoked"        // an API key was administratively soft-revoked; carries type and created_by in Attrs (mirrors api_key.created; no secret)
	APIKeyAuthSucceeded Type = "api_key.auth.succeeded" // an API key was verified successfully; carries key type in Attrs
	APIKeyAuthFailed    Type = "api_key.auth.failed"    // an API key verification failed; Reason carries the failure code (see ReasonAPIKey* constants)
	APIKeyPurged        Type = "api_key.purged"         // expired keys were hard-deleted by the sweep; Attrs carries "count"
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
	// the package avoids importing uuid so any module can emit without coupling.
	TenantID string
	UserID   string
	// Reason is a short machine code for an outcome or failure (e.g. "invalid_credentials",
	// "account_locked", "reuse_after_grace"). Keep it free of secrets and raw user input.
	Reason string
	// Err is the underlying error for failure/outage events (e.g. a swallowed mailer or store
	// error), so an otherwise-invisible outage is observable.
	Err error
	// Attrs carries extra structured context. Never put secrets, tokens or passwords here.
	Attrs map[string]any
}

// Sink receives emitted events. Implementations MUST be safe for concurrent use and SHOULD NOT
// block the caller (buffer or dispatch asynchronously if the backend is slow).
type Sink interface {
	EmitEvent(ctx context.Context, e Event)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(ctx context.Context, e Event)

// EmitEvent implements Sink.
func (f SinkFunc) EmitEvent(ctx context.Context, e Event) { f(ctx, e) }

// Emit sends e to sink when sink is non-nil. Services call it so a nil (unconfigured) sink is a
// cheap no-op and call sites stay free of nil checks.
func Emit(ctx context.Context, sink Sink, e Event) {
	if sink != nil {
		sink.EmitEvent(ctx, e)
	}
}

type multiSink []Sink

// MultiSink returns a Sink that fans every event out to each of sinks (nil entries are skipped).
func MultiSink(sinks ...Sink) Sink { return multiSink(sinks) }

func (m multiSink) EmitEvent(ctx context.Context, e Event) {
	for _, s := range m {
		if s != nil {
			s.EmitEvent(ctx, e)
		}
	}
}

type slogSink struct{ logger *slog.Logger }

// NewSlogSink returns a Sink that logs events to logger (slog.Default() when nil). An event
// carrying an Err is logged at Error; known failure/anomaly events (failed login, lockout,
// refresh reuse, family revoke, MFA verification failure, API-key auth failure, delivery
// failure, insecure-cookie misuse) at Warn; the rest at Info.
func NewSlogSink(logger *slog.Logger) Sink {
	if logger == nil {
		logger = slog.Default()
	}
	return &slogSink{logger: logger}
}

func (s *slogSink) EmitEvent(ctx context.Context, e Event) {
	attrs := make([]slog.Attr, 0, 5+len(e.Attrs))
	attrs = append(attrs, slog.String("event", string(e.Type)))
	if e.TenantID != "" {
		attrs = append(attrs, slog.String("tenant_id", e.TenantID))
	}
	if e.UserID != "" {
		attrs = append(attrs, slog.String("user_id", e.UserID))
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	for k, v := range e.Attrs {
		attrs = append(attrs, slog.Any(k, v))
	}
	if e.Err != nil {
		attrs = append(attrs, slog.Any("error", e.Err))
	}
	s.logger.LogAttrs(ctx, levelFor(e), "egauth security event", attrs...)
}

func levelFor(e Event) slog.Level {
	if e.Err != nil {
		return slog.LevelError
	}
	switch e.Type {
	case LoginFailed, AccountLocked, AccountBlocked, RefreshReuseDetected, TokenFamilyRevoked, MFAVerificationFailed, APIKeyAuthFailed, DeliveryFailed, InsecureCookieMisuse:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// RequestContext carries optional, caller-supplied transport metadata about the request that
// triggered an authentication event — the client IP and User-Agent. The library cannot discover
// these on its own (they live on the inbound HTTP request, which the auth core never sees), so
// the application threads a RequestContext into the auth entry points (login and API-key verify)
// and egauth copies its non-empty fields into Event.Attrs ("ip" / "user_agent") on the resulting
// login.* and api_key.auth.* events.
//
// It is entirely optional: the entry points accept it as a variadic option, so omitting it simply
// omits the corresponding Attrs. Both fields are plain strings and may be left empty individually
// (an empty field is never written to Attrs). RequestContext carries no secrets — an IP and a
// User-Agent are not credentials — so it is consistent with the event package's no-secrets
// contract.
type RequestContext struct {
	// IP is the client IP address as the application observed it (e.g. from RemoteAddr or a
	// trusted proxy header). egauth does not parse, validate or trust it — it is recorded verbatim
	// under the "ip" attribute when non-empty.
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
