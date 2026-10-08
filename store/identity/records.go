package identity

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/JLugagne/egauth/principal"
)

// User is the account row. It is written only through Apply. A zero time means "not set": an
// unverified identifier, an account that is not disabled or not deleted. SecurityEpoch is bumped by
// every security mutation and sealed into every session and bound Pending.
type User struct {
	Subject                 principal.Subject
	Email                   Identifier
	EmailVerifiedAt         time.Time
	Phone                   Identifier
	PhoneVerifiedAt         time.Time
	RecoveryEmail           Identifier
	RecoveryEmailVerifiedAt time.Time
	DisabledAt              time.Time
	DeletedAt               time.Time
	MustChange              bool
	SecurityEpoch           uint64
	CreatedAt               time.Time
}

// PasswordHash is an encoded password hash in PHC string format. The hash sits behind a pointer, so
// fmt prints an address instead of it even when a PasswordHash, or a struct holding one, is nested
// in an unexported field that no String method reaches. The zero value is no hash.
type PasswordHash struct {
	phc *string
}

// NewPasswordHash wraps an encoded PHC string; the empty string gives the zero PasswordHash.
func NewPasswordHash(phc string) PasswordHash {
	if phc == "" {
		return PasswordHash{}
	}
	return PasswordHash{phc: &phc}
}

// PHC returns the encoded hash, for the password verifier and store implementations only; never
// log or return it.
func (h PasswordHash) PHC() string {
	if h.phc == nil {
		return ""
	}
	return *h.phc
}

func (h PasswordHash) IsZero() bool { return h.phc == nil || *h.phc == "" }

// String renders h redacted.
func (h PasswordHash) String() string { return "REDACTED" }

// GoString renders h for %#v redacted.
func (h PasswordHash) GoString() string { return "identity.PasswordHash{REDACTED}" }

// LogValue renders h for slog redacted.
func (h PasswordHash) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// PasswordCredential is the subject's password hash and its lockout counter. Formatting it never
// prints the hash.
type PasswordCredential struct {
	Subject        principal.Subject
	PHC            PasswordHash
	ChangedAt      time.Time
	FailedAttempts int
	LockedUntil    time.Time
}

// String renders c with the hash redacted.
func (c PasswordCredential) String() string {
	return "identity.PasswordCredential{PHC: REDACTED, FailedAttempts: " + strconv.Itoa(c.FailedAttempts) + "}"
}

// GoString renders c for %#v with the hash redacted.
func (c PasswordCredential) GoString() string { return c.String() }

// LogValue renders c for slog with the hash redacted.
func (c PasswordCredential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("phc", "REDACTED"),
		slog.Int("failed_attempts", c.FailedAttempts),
		slog.Time("locked_until", c.LockedUntil),
	)
}

// LockoutPolicy is the password lockout applied by RecordPasswordFailure: Threshold failures within
// Window lock the credential for Window. A non-positive Threshold or Window is refused with
// ErrInvalidMutation, so a lockout cannot be switched off by a zero value.
type LockoutPolicy struct {
	Threshold int
	Window    time.Duration
}

// Lockout is the counter after a recorded failure. JustLocked is true for exactly one of concurrent
// failures: the one that crossed Threshold.
type Lockout struct {
	FailedAttempts int
	LockedUntil    time.Time
	JustLocked     bool
}

// FederatedIdentity is an account at an external identity provider. ProviderEmail is the address
// the provider asserted, zero when none, and is never used to link an existing account (D6).
type FederatedIdentity struct {
	Provider              string
	ProviderSubject       string
	ProviderEmail         Identifier
	ProviderEmailVerified bool
}

// FederatedKey finds the link of one provider account.
type FederatedKey struct {
	Tenant          principal.TenantID
	Provider        string
	ProviderSubject string
}

// FederatedLink binds a FederatedIdentity to a subject; it is written only by CreateVerified,
// LinkFederated and UnlinkFederated.
type FederatedLink struct {
	Subject  principal.Subject
	Identity FederatedIdentity
	LinkedAt time.Time
}
