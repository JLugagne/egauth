// Package mfa holds the persistence contract of TOTP enrollments and recovery codes. Stores keep the
// sealed secret as opaque bytes and never see a KEK.
package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

const (
	// AADVersionLegacy marks a secret sealed by v0.16, before associated data was mandatory.
	AADVersionLegacy uint8 = 0
	// AADVersionCurrent marks a secret sealed under the v0.17 format.
	AADVersionCurrent uint8 = 1
)

// ErrLegacyAADVersion reports an enrollment written with an AADVersion other than AADVersionCurrent:
// v0.16 secrets are only ever read and re-sealed, never written fresh, so startup never meets a new
// v0 row (C-58).
var ErrLegacyAADVersion = errors.New("mfa: new secrets must use AADVersionCurrent")

// Enrollment is a subject's TOTP factor. An unconfirmed enrollment never satisfies a second-factor
// check.
type Enrollment struct {
	Subject        principal.Subject
	Sealed         []byte
	AADVersion     uint8
	ConfirmedAt    *time.Time
	LastUsedStep   int64
	FailedAttempts int
	LastAttemptAt  time.Time
	CreatedAt      time.Time
}

func (e Enrollment) Confirmed() bool { return e.ConfirmedAt != nil }

// Lockout is the budget charged by an Increment call.
type Lockout struct {
	Subject  principal.Subject
	Now      time.Time
	Max      int
	Duration time.Duration
}

// SealedRef addresses the sealed secret of one enrollment.
type SealedRef struct {
	Subject principal.Subject
}

// V016Row is a v0.16-sealed enrollment awaiting upgrade.
type V016Row struct {
	Ref    SealedRef
	Sealed []byte
}

// Reseal is the compare-and-swap of a sealed secret: Old is the exact sealed bytes that were read,
// so a secret replaced in the meantime (re-enrollment, a concurrent upgrade) is never overwritten.
type Reseal struct {
	Ref SealedRef
	Old []byte
	New []byte
}

// Store persists TOTP enrollments, recovery codes and their lockout counters.
//
// The per-subject lockouts and the LastUsedStep replay guard are mandatory: the counters survive
// flow restarts and are shared by every verification path (C-40).
type Store interface {
	store.Base

	// SaveTOTP upserts the subject's enrollment, one per subject. It is for enrollment only: a
	// re-seal goes through ReplaceSealed, so the replay guard and the counters are never rolled back.
	// It returns ErrLegacyAADVersion when e.AADVersion is not AADVersionCurrent.
	SaveTOTP(ctx context.Context, e Enrollment) error
	// GetTOTP returns the enrollment, or store.ErrNotFound.
	GetTOTP(ctx context.Context, s principal.Subject) (Enrollment, error)
	// DeleteTOTP removes the enrollment. It is idempotent.
	DeleteTOTP(ctx context.Context, s principal.Subject) error
	// HasConfirmedTOTP reports whether the subject has a confirmed enrollment.
	HasConfirmedTOTP(ctx context.Context, s principal.Subject) (bool, error)
	// AnyEnrolled reports whether any subject of any tenant has a TOTP enrollment, confirmed or not,
	// or an unused recovery code. New refuses to start on true while the MFA module is absent (C-01).
	AnyEnrolled(ctx context.Context) (bool, error)
	// CountEnrolled returns how many subjects of all tenants AnyEnrolled counts, for the message of
	// that startup refusal.
	CountEnrolled(ctx context.Context) (int64, error)
	// MarkTOTPUsed records step only if it is strictly greater than LastUsedStep, and reports whether
	// it applied; false means replay. On success it resets the failed-attempt counter.
	MarkTOTPUsed(ctx context.Context, s principal.Subject, step int64) (bool, error)
	// IncrementTOTPAttempts atomically reserves one attempt before the comparison and returns the new
	// count. A locked factor that has not decayed keeps its count and LastAttemptAt. It returns
	// store.ErrNotFound without an enrollment.
	IncrementTOTPAttempts(ctx context.Context, l Lockout) (int, error)
	// ResetTOTPAttempts clears the counter, for lockout decay and the administrative unlock.
	ResetTOTPAttempts(ctx context.Context, s principal.Subject) error
	// ConfirmEnrollment confirms the enrollment and stores its recovery code hashes in one
	// transaction: both happen or neither does. It returns ErrLegacyAADVersion when e.AADVersion is
	// not AADVersionCurrent.
	ConfirmEnrollment(ctx context.Context, e Enrollment, codeHashes []string) error

	// ReplaceRecoveryCodes atomically discards the subject's codes and stores codeHashes.
	ReplaceRecoveryCodes(ctx context.Context, s principal.Subject, codeHashes []string) error
	// ConsumeRecoveryCode marks the matching unused code used, resets the TOTP counter, and returns
	// store.ErrNotFound when no unused code matches.
	ConsumeRecoveryCode(ctx context.Context, s principal.Subject, codeHash string) error
	// DeleteRecoveryCodes removes every code of the subject. It is idempotent.
	DeleteRecoveryCodes(ctx context.Context, s principal.Subject) error
	// IncrementRecoveryAttempts is the recovery-code counterpart of IncrementTOTPAttempts, isolated
	// from the TOTP counter. It works without a TOTP enrollment.
	IncrementRecoveryAttempts(ctx context.Context, l Lockout) (int, error)
	// ResetRecoveryAttempts clears the recovery counter.
	ResetRecoveryAttempts(ctx context.Context, s principal.Subject) error

	// DeleteForSubject removes the enrollment, recovery codes and counters. It is idempotent.
	DeleteForSubject(ctx context.Context, s principal.Subject) error

	// CountLegacySealed returns how many enrollments still have aad_version 0.
	CountLegacySealed(ctx context.Context) (int64, error)
	// V016Sealed returns up to limit aad_version 0 enrollments after the cursor, with the cursor of
	// the last one. The zero cursor starts from the beginning. DESIGN section 4.7 calls it
	// LegacySealed(cursor).
	V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]V016Row, store.Cursor, error)
	// ReplaceSealed stores r.New and sets aad_version to AADVersionCurrent only while the stored
	// sealed bytes still equal r.Old, and reports whether it did. It serves both the v0.16 upgrade
	// and the lazy re-seal after a KEK rotation, and touches neither LastUsedStep nor the counters.
	ReplaceSealed(ctx context.Context, r Reseal) (bool, error)
}
