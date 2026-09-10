package mfa

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// TOTPEnrollment carries the shared TOTP secret in the exported Secret field. The secret is
// stored recoverably so the server can recompute codes, which makes an accidental config/enrollment
// dump — log.Printf("%+v", e), slog.Any — a credential leak. The methods below make the common
// accidental-leak paths safe by default: fmt verbs (%v/%s/%+v/%#v) and slog (via slog.LogValuer)
// render Secret as a placeholder, while the non-secret lifecycle fields stay visible to aid
// debugging.
//
// NOTE: like the other key-bearing types, JSON marshalling is intentionally NOT redacted — the
// mfa store backends persist Secret explicitly through their own paths. Treat Secret as a
// credential and never log or serialize an enrollment. See SECURITY.md.
func (e TOTPEnrollment) String() string {
	secret := redacted
	if e.Secret == "" {
		secret = "" // distinguish "unset" from "set-but-hidden" without leaking
	}
	return fmt.Sprintf(
		"TOTPEnrollment{UserID:%s TenantID:%s Secret:%s ConfirmedAt:%v LastUsedStep:%d "+
			"FailedAttempts:%d LastAttemptAt:%s CreatedAt:%s}",
		e.UserID, e.TenantID, secret, e.ConfirmedAt, e.LastUsedStep, e.FailedAttempts,
		e.LastAttemptAt, e.CreatedAt,
	)
}

// GoString redacts the %#v representation.
func (e TOTPEnrollment) GoString() string { return e.String() }

// LogValue redacts the TOTPEnrollment for structured (slog) logging.
func (e TOTPEnrollment) LogValue() slog.Value {
	secret := redacted
	if e.Secret == "" {
		secret = ""
	}
	return slog.GroupValue(
		slog.String("user_id", e.UserID.String()),
		slog.String("tenant_id", e.TenantID),
		slog.String("secret", secret),
		slog.Time("created_at", e.CreatedAt),
	)
}
