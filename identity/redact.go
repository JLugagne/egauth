package identity

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

// redacted is the placeholder substituted for credential material in log/print output.
const redacted = "REDACTED"

// The delivery payloads below carry a freshly minted single-use credential in an exported Token
// field. They are handed to the application's Mailer/SMSSender, and the canonical implementation of
// those callbacks during development — and in plenty of production deployments — is a console mailer
// that prints its argument. A printed payload is a working credential: the reset token drives
// ResetPasswordHandler, the magic-link token completes a login, and the verification tokens confirm
// an address.
//
// These types therefore implement the same redaction contract as the rest of the module's
// credential-bearing types (%v/%s/%+v/%#v via String/GoString, and slog via LogValue). Value
// receivers cover both the value and pointer forms. Non-secret context — the recipient, the pending
// address — stays visible so a log line is still useful.
//
// Delivery code that needs the token reads the field directly, as the mailer otherwise could not do
// its job. JSON marshalling is deliberately not redacted, for the same reason it is not redacted on
// the other credential types: serializing a payload to actually send it is the legitimate use.

// String redacts PasswordResetMail.
func (m PasswordResetMail) String() string {
	return fmt.Sprintf("PasswordResetMail{User:%s Token:%s}", userRef(m.User), redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m PasswordResetMail) GoString() string { return m.String() }

// LogValue redacts PasswordResetMail for structured (slog) logging.
func (m PasswordResetMail) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("user", userRef(m.User)), slog.String("token", redactToken(m.Token)))
}

// String redacts EmailVerificationMail.
func (m EmailVerificationMail) String() string {
	return fmt.Sprintf("EmailVerificationMail{User:%s Token:%s}", userRef(m.User), redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m EmailVerificationMail) GoString() string { return m.String() }

// LogValue redacts EmailVerificationMail for structured (slog) logging.
func (m EmailVerificationMail) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("user", userRef(m.User)), slog.String("token", redactToken(m.Token)))
}

// String redacts MagicLinkMail.
func (m MagicLinkMail) String() string {
	return fmt.Sprintf("MagicLinkMail{User:%s Token:%s}", userRef(m.User), redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m MagicLinkMail) GoString() string { return m.String() }

// LogValue redacts MagicLinkMail for structured (slog) logging.
func (m MagicLinkMail) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("user", userRef(m.User)), slog.String("token", redactToken(m.Token)))
}

// String redacts EmailChangeMail, keeping the pending address visible because it is the recipient
// the message must reach, not a secret.
func (m EmailChangeMail) String() string {
	return fmt.Sprintf("EmailChangeMail{User:%s NewEmail:%s Token:%s}",
		userRef(m.User), m.NewEmail, redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m EmailChangeMail) GoString() string { return m.String() }

// LogValue redacts EmailChangeMail for structured (slog) logging.
func (m EmailChangeMail) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("user", userRef(m.User)),
		slog.String("new_email", m.NewEmail),
		slog.String("token", redactToken(m.Token)),
	)
}

// String redacts RecoveryEmailMail, keeping the candidate address visible.
func (m RecoveryEmailMail) String() string {
	return fmt.Sprintf("RecoveryEmailMail{User:%s RecoveryEmail:%s Token:%s}",
		userRef(m.User), m.RecoveryEmail, redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m RecoveryEmailMail) GoString() string { return m.String() }

// LogValue redacts RecoveryEmailMail for structured (slog) logging.
func (m RecoveryEmailMail) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("user", userRef(m.User)),
		slog.String("recovery_email", m.RecoveryEmail),
		slog.String("token", redactToken(m.Token)),
	)
}

// String redacts PhoneVerificationSMS, keeping the destination number visible.
func (m PhoneVerificationSMS) String() string {
	return fmt.Sprintf("PhoneVerificationSMS{User:%s Phone:%s Token:%s}",
		userRef(m.User), m.Phone, redactToken(m.Token))
}

// GoString redacts the %#v representation.
func (m PhoneVerificationSMS) GoString() string { return m.String() }

// LogValue redacts PhoneVerificationSMS for structured (slog) logging.
func (m PhoneVerificationSMS) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("user", userRef(m.User)),
		slog.String("phone", m.Phone),
		slog.String("token", redactToken(m.Token)),
	)
}

// redactToken hides a credential while keeping the empty-vs-set distinction visible: an operator
// debugging a missing token can tell "not minted" from "minted but hidden".
func redactToken(token string) string {
	if token == "" {
		return ""
	}
	return redacted
}

// userRef renders the account reference without depending on User's own formatting, and tolerates
// the nil user that a zero-value payload carries.
func userRef(u *User) string {
	if u == nil {
		return "<nil>"
	}
	if u.ID == uuid.Nil {
		return "<no-id>"
	}
	return u.ID.String()
}

// Identity is the per-provider login binding attached to a user, and it carries the stored password
// hash. A hash is not a usable credential the way a plaintext token is, but a leaked one enables
// offline cracking and, for a shared or weak password, immediate reuse — and a user record is a very
// ordinary thing to print while debugging a login failure. Redacting it costs nothing and keeps the
// non-secret binding fields (provider, provider id, timestamps) visible.
func (i Identity) String() string {
	hash := ""
	if i.PasswordHash != nil {
		hash = redacted
	}
	return fmt.Sprintf("Identity{ID:%s UserID:%s TenantID:%s Provider:%s ProviderID:%s PasswordHash:%s CreatedAt:%v UpdatedAt:%v}",
		i.ID, i.UserID, i.TenantID, i.Provider, i.ProviderID, hash, i.CreatedAt, i.UpdatedAt)
}

// GoString redacts the %#v representation.
func (i Identity) GoString() string { return i.String() }

// LogValue redacts Identity for structured (slog) logging.
func (i Identity) LogValue() slog.Value {
	hashSet := i.PasswordHash != nil
	return slog.GroupValue(
		slog.String("user_id", i.UserID.String()),
		slog.String("tenant_id", i.TenantID),
		slog.String("provider", i.Provider),
		slog.String("provider_id", i.ProviderID),
		slog.Bool("password_hash_set", hashSet),
	)
}
