// Package event defines egauth's optional security-event seam. Services emit lifecycle and
// security events — login success/failure, account lockout, refresh-token reuse, MFA changes,
// delivery failures, ... — to a Sink the application supplies. It is entirely optional (a nil
// Sink disables emission) and dependency-free, so any module can emit without coupling to a
// particular logging or telemetry implementation.
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
	LoginSucceeded        Type = "login.succeeded"
	LoginFailed           Type = "login.failed"
	AccountLocked         Type = "account.locked"
	UserRegistered        Type = "user.registered"
	PasswordReset         Type = "password.reset"   // completed via a reset token
	PasswordChanged       Type = "password.changed" // authenticated self-service change
	EmailVerified         Type = "email.verified"
	EmailChanged          Type = "email.changed"
	MagicLinkLogin        Type = "magic_link.login"
	AccountDeleted        Type = "account.deleted"
	RefreshReuseDetected  Type = "refresh.reuse_detected"
	TokenFamilyRevoked    Type = "token.family_revoked"
	MFAEnrolled           Type = "mfa.enrolled"
	MFAConfirmed          Type = "mfa.confirmed"
	MFAVerificationFailed Type = "mfa.verification_failed"
	MFADisabled           Type = "mfa.disabled"
	DeliveryFailed        Type = "delivery.failed" // a swallowed mailer/delivery error (outage signal)
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
// refresh reuse, family revoke, MFA verification failure, delivery failure) at Warn; the rest at
// Info.
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
	case LoginFailed, AccountLocked, RefreshReuseDetected, TokenFamilyRevoked, MFAVerificationFailed, DeliveryFailed:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}
