package otp

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// String renders the challenge with the one-time code redacted. The plaintext code stays
// available through the exported Code field for delivery; it is merely kept out of ad-hoc
// formatting and logs. See Challenge's doc comment: treat Code as a credential.
func (c Challenge) String() string {
	return fmt.Sprintf("otp.Challenge{SubjectID:%s TenantID:%s Purpose:%s Code:%s ExpiresAt:%s}",
		c.SubjectID, c.TenantID, c.Purpose, redacted, c.ExpiresAt)
}

// GoString keeps %#v output free of the one-time code.
func (c Challenge) GoString() string { return c.String() }

// LogValue redacts the one-time code for structured (slog) logging.
func (c Challenge) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("subject_id", c.SubjectID.String()),
		slog.String("tenant_id", c.TenantID),
		slog.String("purpose", c.Purpose),
		slog.String("code", redacted),
		slog.Time("expires_at", c.ExpiresAt),
	)
}

// String renders the stored OTP record with its code hash redacted. Attempt counts and
// timestamps are retained because they are not secret.
func (o OTP) String() string {
	return fmt.Sprintf("otp.OTP{SubjectID:%s TenantID:%s Purpose:%s CodeHash:%s Attempts:%d ExpiresAt:%s CreatedAt:%s}",
		o.SubjectID, o.TenantID, o.Purpose, redacted, o.Attempts, o.ExpiresAt, o.CreatedAt)
}

// GoString keeps %#v output free of the stored code hash.
func (o OTP) GoString() string { return o.String() }

// LogValue redacts the stored code hash for structured (slog) logging.
func (o OTP) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("subject_id", o.SubjectID.String()),
		slog.String("tenant_id", o.TenantID),
		slog.String("purpose", o.Purpose),
		slog.String("code_hash", redacted),
		slog.Int("attempts", o.Attempts),
		slog.Time("expires_at", o.ExpiresAt),
		slog.Time("created_at", o.CreatedAt),
	)
}
