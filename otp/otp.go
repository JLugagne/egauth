// Package otp implements short numeric one-time passcodes (e.g. email or SMS OTP) for
// passwordless login, verification or step-up. It is deliberately DELIVERY-AGNOSTIC: egauth
// never sends anything. Issue returns a Challenge containing the plaintext code (and the data
// needed to compose the message); the application delivers it over whatever channel it likes
// and later calls Verify. Only the code's hash is stored, and verification is single-use and
// attempt-limited.
//
// It follows egauth's conventions — a Store interface (memory + pgx implementations with a
// shared contract) and a Service for orchestration — and depends only on the standard library
// plus google/uuid.
package otp

import (
	"time"

	"github.com/google/uuid"
)

// Defaults for issued codes.
const (
	// DefaultDigits is the length of a generated numeric code.
	DefaultDigits = 6
	// DefaultTTL is how long an issued code remains valid.
	DefaultTTL = 10 * time.Minute
	// DefaultMaxAttempts is how many wrong guesses are tolerated before the code is burned.
	DefaultMaxAttempts = 5
	// DefaultCooldown is how long a subject must wait before requesting another code for the same purpose.
	DefaultCooldown = 30 * time.Second
)

// Challenge is everything the application needs to deliver a one-time passcode. egauth does
// NOT send it — Issue returns it so the caller can put Code into an email/SMS/etc. Code is the
// plaintext passcode, returned exactly once (only its hash is persisted); treat it as a
// credential and never log it.
type Challenge struct {
	SubjectID uuid.UUID
	TenantID  string
	Purpose   string
	Code      string
	ExpiresAt time.Time
}

// OTP is the stored record for an outstanding passcode (one per subject+purpose). Only the
// hash of the code is kept.
type OTP struct {
	SubjectID uuid.UUID
	TenantID  string
	Purpose   string
	CodeHash  string
	Attempts  int
	ExpiresAt time.Time
	CreatedAt time.Time
}
