package mfa

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output. It matches the
// placeholder used by tokens/redact.go so a deployment greps for one token.
const redacted = "REDACTED"

// A TOTP shared secret cannot be hashed — the server recomputes the expected code from it — so it
// lives in memory (and in the database) in a recoverable form, and anything that renders it is a
// full compromise of the second factor. The methods below make the common accidental-leak paths safe
// by default: fmt verbs (%v/%+v/%s/%#v) and slog (via slog.LogValuer) render a placeholder. The
// provisioning URI is redacted with the secret because it EMBEDS it (otpauth://…?secret=…).
//
// NOTE: JSON marshalling is intentionally NOT redacted — returning the freshly minted secret and URI
// to the enrolling user is the whole point of EnrollTOTP. Rely on the redaction here when logging.

// String renders the enrollment with its shared secret redacted.
func (e TOTPEnrollment) String() string {
	confirmed := "<nil>"
	if e.ConfirmedAt != nil {
		confirmed = e.ConfirmedAt.String()
	}
	return fmt.Sprintf("TOTPEnrollment{UserID:%s TenantID:%s Secret:%s ConfirmedAt:%s LastUsedStep:%d FailedAttempts:%d LastAttemptAt:%s CreatedAt:%s}",
		e.UserID, e.TenantID, redacted, confirmed, e.LastUsedStep, e.FailedAttempts, e.LastAttemptAt, e.CreatedAt)
}

// GoString redacts the %#v representation.
func (e TOTPEnrollment) GoString() string { return e.String() }

// LogValue redacts the shared secret for structured (slog) logging.
func (e TOTPEnrollment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user_id", e.UserID.String()),
		slog.String("tenant_id", e.TenantID),
		slog.String("secret", redacted),
		slog.Bool("confirmed", e.ConfirmedAt != nil),
		slog.Int64("last_used_step", e.LastUsedStep),
		slog.Int("failed_attempts", e.FailedAttempts),
	)
}

// String renders the minted enrollment with both the shared secret and the provisioning URI (which
// embeds it) redacted.
func (e Enrollment) String() string {
	return fmt.Sprintf("Enrollment{Secret:%s URI:%s}", redacted, redacted)
}

// GoString redacts the %#v representation.
func (e Enrollment) GoString() string { return e.String() }

// LogValue redacts the shared secret and provisioning URI for structured (slog) logging.
func (e Enrollment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("secret", redacted),
		slog.String("uri", redacted),
	)
}
