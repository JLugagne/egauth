package egauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/google/uuid"
)

// EmailDeliverer sends one email per message kind. Every method must be safe for concurrent use and
// idempotent on DeliveryID, which is stable across retries. A kind added in a later release is a
// compile error in the integrator's code, not a dropped message.
type EmailDeliverer interface {
	RegistrationLink(ctx context.Context, m LinkMessage) error
	AccountExistsNotice(ctx context.Context, m NoticeMessage) error
	PasswordResetLink(ctx context.Context, m LinkMessage) error
	MagicLink(ctx context.Context, m LinkMessage) error
	// LoginCode sends an emailed sign-in code; it yields the email_code factor, never sms_code.
	LoginCode(ctx context.Context, m CodeMessage) error
	EmailVerificationLink(ctx context.Context, m LinkMessage) error
	EmailChangeLink(ctx context.Context, m LinkMessage) error
	RecoveryEmailLink(ctx context.Context, m LinkMessage) error
	SecurityNotice(ctx context.Context, m SecurityNoticeMessage) error
}

// SMSDeliverer sends one text message per message kind; its contract mirrors EmailDeliverer.
type SMSDeliverer interface {
	// LoginCode sends a texted sign-in code; it yields the sms_code factor, never email_code.
	LoginCode(ctx context.Context, m CodeMessage) error
	PhoneVerificationCode(ctx context.Context, m CodeMessage) error
	// PasswordResetCode sends a texted reset code; it never admits a session and is never accepted
	// as a sign-in code.
	PasswordResetCode(ctx context.Context, m CodeMessage) error
	SecurityNotice(ctx context.Context, m SecurityNoticeMessage) error
}

const redactedSecret = "REDACTED"

// LinkMessage carries a one-time link built from the public origin, base path and pages. Link is a
// bearer credential until it expires: fmt and slog render it as REDACTED, so a console deliverer
// that prints the message does not log a working link. Deliverers read the field directly.
type LinkMessage struct {
	DeliveryID uuid.UUID
	Tenant     principal.TenantID
	To         string
	Link       string
	ExpiresAt  time.Time
}

// CodeMessage carries a short numeric code the recipient types back. fmt and slog render Code as
// REDACTED; deliverers read the field directly.
type CodeMessage struct {
	DeliveryID uuid.UUID
	Tenant     principal.TenantID
	To         string
	Code       string
	ExpiresAt  time.Time
}

// NoticeMessage tells the recipient that something happened, without a secret.
type NoticeMessage struct {
	DeliveryID uuid.UUID
	Tenant     principal.TenantID
	To         string
}

// SecurityEvent classifies a security notice. Values are never renumbered or reused. An integrator
// must treat an unrecognised value as a generic notice and show Summary.
type SecurityEvent uint8

const (
	SecurityCredentialRotated SecurityEvent = 1
	SecurityFactorsChanged    SecurityEvent = 2
	SecurityIdentifierChanged SecurityEvent = 3
)

// String returns the snake_case name of e, or "invalid".
func (e SecurityEvent) String() string {
	switch e {
	case SecurityCredentialRotated:
		return "credential_rotated"
	case SecurityFactorsChanged:
		return "factors_changed"
	case SecurityIdentifierChanged:
		return "identifier_changed"
	}
	return "invalid"
}

// ClientInfo describes the client that triggered a security-relevant change; either field may be
// empty.
type ClientInfo struct {
	IP        netip.Addr
	UserAgent string
}

// SecurityNoticeMessage tells the account owner that a security-relevant change happened. Summary
// is library-rendered English so that an unrecognised Event still produces a meaningful message.
// RevertLink undoes the change for days, so fmt and slog render it as REDACTED; deliverers read the
// field directly.
type SecurityNoticeMessage struct {
	DeliveryID uuid.UUID
	Tenant     principal.TenantID
	To         string
	Event      SecurityEvent
	Summary    string
	RevertLink string
	OccurredAt time.Time
	Client     ClientInfo
}

// String renders m with Link redacted.
func (m LinkMessage) String() string {
	return fmt.Sprintf("LinkMessage{DeliveryID:%s Tenant:%s To:%s Link:%s ExpiresAt:%s}",
		m.DeliveryID, m.Tenant, m.To, redactedSecret, m.ExpiresAt.Format(time.RFC3339))
}

// GoString renders m for %#v with Link redacted.
func (m LinkMessage) GoString() string { return m.String() }

// LogValue renders m for slog with Link redacted.
func (m LinkMessage) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("delivery_id", m.DeliveryID.String()),
		slog.String("tenant", m.Tenant.String()),
		slog.String("to", m.To),
		slog.String("link", redactedSecret),
		slog.Time("expires_at", m.ExpiresAt),
	)
}

// String renders m with Code redacted.
func (m CodeMessage) String() string {
	return fmt.Sprintf("CodeMessage{DeliveryID:%s Tenant:%s To:%s Code:%s ExpiresAt:%s}",
		m.DeliveryID, m.Tenant, m.To, redactedSecret, m.ExpiresAt.Format(time.RFC3339))
}

// GoString renders m for %#v with Code redacted.
func (m CodeMessage) GoString() string { return m.String() }

// LogValue renders m for slog with Code redacted.
func (m CodeMessage) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("delivery_id", m.DeliveryID.String()),
		slog.String("tenant", m.Tenant.String()),
		slog.String("to", m.To),
		slog.String("code", redactedSecret),
		slog.Time("expires_at", m.ExpiresAt),
	)
}

// String renders m with RevertLink redacted.
func (m SecurityNoticeMessage) String() string {
	return fmt.Sprintf("SecurityNoticeMessage{DeliveryID:%s Tenant:%s To:%s Event:%s Summary:%q RevertLink:%s "+
		"OccurredAt:%s Client:{IP:%s UserAgent:%q}}",
		m.DeliveryID, m.Tenant, m.To, m.Event, m.Summary, redactedSecret,
		m.OccurredAt.Format(time.RFC3339), m.Client.IP, m.Client.UserAgent)
}

// GoString renders m for %#v with RevertLink redacted.
func (m SecurityNoticeMessage) GoString() string { return m.String() }

// LogValue renders m for slog with RevertLink redacted.
func (m SecurityNoticeMessage) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("delivery_id", m.DeliveryID.String()),
		slog.String("tenant", m.Tenant.String()),
		slog.String("to", m.To),
		slog.String("event", m.Event.String()),
		slog.String("summary", m.Summary),
		slog.String("revert_link", redactedSecret),
		slog.Time("occurred_at", m.OccurredAt),
		slog.String("client_ip", m.Client.IP.String()),
		slog.String("client_user_agent", m.Client.UserAgent),
	)
}
