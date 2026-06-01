package identity

import (
	"time"

	"github.com/google/uuid"
)

// User represents an account container.
// User represents an account container.
// User represents an account container.
type User struct {
	ID              uuid.UUID
	TenantID        string
	Email           string
	EmailVerifiedAt *time.Time
	// Phone is the account's optional phone number in normalized E.164 form (nil when none has
	// been enrolled). It is a lower-assurance contact channel: per NIST SP 800-63B the mfa module
	// deliberately does NOT accept SMS as an authentication factor, but a verified phone number is
	// still useful for transactional notifications and as an independent recovery channel.
	Phone *string
	// PhoneVerifiedAt records when control of Phone was last proven (nil when unverified). It is
	// set by ConfirmPhoneVerification and cleared whenever Phone changes to a new, unverified value.
	PhoneVerifiedAt *time.Time
	// RecoveryEmail is an optional SECONDARY email address (nil when none is enrolled), distinct
	// from the primary login Email, used as an independent account-recovery channel. Holding a
	// verified recovery channel that is separate from the primary email breaks the single-email
	// takeover chain: losing or compromising the primary mailbox no longer implies losing the
	// account, and a recovery-channel reset cannot be driven from the primary inbox alone.
	RecoveryEmail *string
	// RecoveryEmailVerifiedAt records when control of RecoveryEmail was last proven (nil when
	// unverified). Only a VERIFIED recovery channel counts toward recovery; it is set by
	// ConfirmRecoveryEmail and cleared whenever RecoveryEmail changes to a new, unverified value.
	RecoveryEmailVerifiedAt *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
	DeletedAt               *time.Time
}

// Identity represents an authentication method linked to a User.
type Identity struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     string
	Provider     string  // e.g., "password", "google", "github"
	ProviderID   string  // e.g., email for "password", "sub" for OAuth
	PasswordHash *string // Only populated for "password" provider
	// FailedAttempts is the number of consecutive failed authentication attempts.
	FailedAttempts int
	// LockedUntil, when set and in the future, blocks authentication for this identity.
	LockedUntil *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
