package pgx

import (
	"context"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/mfa"
)

// NewStore creates a new PostgreSQL mfa store. The KEK is REQUIRED: it envelope-encrypts the
// TOTP shared secret at rest. NewStore panics on a nil KEK so a misconfigured deployment cannot
// start in a mode that would persist the second-factor seed in plaintext.
func NewStore(db DBQuerier, kek *keystore.KEK) *Store {
	if kek == nil {
		panic("pgx mfa: a non-nil KEK is required (TOTP secret-at-rest encryption is mandatory)")
	}
	return &Store{db: db, kek: kek}
}

// ErrSecretCorrupt is returned by GetTOTP when the stored TOTP secret cannot be decrypted with
// the configured KEK — it was sealed under a different KEK, the column was tampered with, or it
// is a legacy plaintext row predating secret-at-rest encryption. The store fails CLOSED: it
// never hands back a wrong or unverifiable secret. It wraps keystore.ErrCiphertextCorrupt so
// callers can match either sentinel.
var ErrSecretCorrupt = fmt.Errorf("pgx mfa: stored TOTP secret could not be decrypted: %w", keystore.ErrCiphertextCorrupt)

// sealSecret envelope-encrypts the base32 TOTP seed for storage.
func (s *Store) sealSecret(secret string) ([]byte, error) {
	return s.kek.Seal([]byte(secret))
}

// openSecret reverses sealSecret. It fails closed (ErrSecretCorrupt) on any decryption failure,
// never returning a wrong or partial secret.
func (s *Store) openSecret(sealed []byte) (string, error) {
	pt, err := s.kek.Open(sealed)
	if err != nil {
		return "", ErrSecretCorrupt
	}
	return string(pt), nil
}

func (s *Store) SaveTOTP(ctx context.Context, tenantID string, e *mfa.TOTPEnrollment) error {
	if e.TenantID != "" && e.TenantID != tenantID {
		return mfa.ErrTenantMismatch
	}
	e.TenantID = tenantID
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	// Envelope-encrypt the base32 seed so a database dump never yields a usable second factor.
	sealedSecret, err := s.sealSecret(e.Secret)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, user_id) DO UPDATE
		SET secret = EXCLUDED.secret,
		    confirmed_at = EXCLUDED.confirmed_at,
		    last_used_step = EXCLUDED.last_used_step,
		    failed_attempts = EXCLUDED.failed_attempts,
		    last_attempt_at = EXCLUDED.last_attempt_at
	`
	var lastAttemptAt *time.Time
	if !e.LastAttemptAt.IsZero() {
		t := e.LastAttemptAt.UTC()
		lastAttemptAt = &t
	}
	_, err = s.db.Exec(ctx, query, tenantID, e.UserID, sealedSecret, e.ConfirmedAt, e.LastUsedStep, e.FailedAttempts, lastAttemptAt, e.CreatedAt)
	return err
}

// Store implements mfa.Store for PostgreSQL.
//
// The TOTP shared secret is envelope-encrypted at rest: SaveTOTP seals the base32 seed with the
// deployment KEK (AES-256-GCM) before insert and GetTOTP opens it after read, so a database dump
// alone never yields a usable second factor. The KEK is REQUIRED — NewStore panics on a nil KEK.
type Store struct {
	db  DBQuerier
	kek *keystore.KEK
}
