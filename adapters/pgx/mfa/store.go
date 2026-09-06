// Package pgx provides a PostgreSQL-backed mfa.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the mfa module's Postgres schema,
// applied via Migrate (which runs them through pgxmigrate).
//
//go:embed migrations/*.sql
var MigrationsFS embed.FS

// Migrate applies the embedded SQL migrations against db, skipping any already recorded in the
// schema_migrations table — so re-running it is a no-op. See internal/pgxmigrate for the
// migration-authoring contract (idempotent, single-transaction, never-edit-applied files).
func Migrate(ctx context.Context, db DBQuerier) error {
	return pgxmigrate.Run(ctx, db, MigrationsFS)
}

// DBQuerier matches both *pgxpool.Pool and pgx.Tx.
type DBQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// KEK provides envelope encryption for TOTP secrets at rest.
type KEK interface {
	Seal(plaintext []byte, aad ...[]byte) ([]byte, error)
	Open(sealed []byte, aad ...[]byte) ([]byte, error)
}

// Store implements mfa.Store for PostgreSQL.
type Store struct {
	db  DBQuerier
	kek KEK
}

// NewStore creates a new PostgreSQL mfa store.
func NewStore(db DBQuerier, kek KEK) *Store {
	if kek == nil {
		panic("mfa pgx: KEK is required")
	}
	return &Store{db: db, kek: kek}
}

func totpAAD(tenantID string, userID uuid.UUID) []byte {
	return []byte(tenantID + ":" + userID.String())
}

func (s *Store) sealSecret(secret string, aad []byte) ([]byte, error) {
	if withAAD, ok := s.kek.(interface {
		SealWithAAD(plaintext []byte, aad []byte) ([]byte, error)
	}); ok {
		return withAAD.SealWithAAD([]byte(secret), aad)
	}
	return s.kek.Seal([]byte(secret), aad)
}

func (s *Store) openSecret(sealed []byte, aad []byte) ([]byte, error) {
	if withAAD, ok := s.kek.(interface {
		OpenWithAAD(sealed []byte, aad []byte) ([]byte, error)
	}); ok {
		pt, err := withAAD.OpenWithAAD(sealed, aad)
		if err == nil {
			return pt, nil
		}
		// Fallback without AAD for backward-compatibility with legacy unauthenticated secrets
		if withoutAAD, ok := s.kek.(interface {
			Open(sealed []byte, aad ...[]byte) ([]byte, error)
		}); ok {
			if fallbackPt, fallbackErr := withoutAAD.Open(sealed); fallbackErr == nil {
				return fallbackPt, nil
			}
		}
		return nil, err
	}
	pt, err := s.kek.Open(sealed, aad)
	if err != nil {
		// Fallback without AAD for backward-compatibility with legacy unauthenticated secrets
		if fallbackPt, fallbackErr := s.kek.Open(sealed); fallbackErr == nil {
			return fallbackPt, nil
		}
		return nil, err
	}
	return pt, nil
}

func (s *Store) SaveTOTP(ctx context.Context, tenantID string, e *mfa.TOTPEnrollment) error {
	if e.TenantID != "" && e.TenantID != tenantID {
		return mfa.ErrTenantMismatch
	}
	e.TenantID = tenantID
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
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

	sealed, err := s.sealSecret(e.Secret, totpAAD(tenantID, e.UserID))
	if err != nil {
		return fmt.Errorf("mfa pgx: sealing secret: %w", err)
	}
	secretStr := base64.StdEncoding.EncodeToString(sealed)

	_, err = s.db.Exec(ctx, query, tenantID, e.UserID, secretStr, e.ConfirmedAt, e.LastUsedStep, e.FailedAttempts, lastAttemptAt, e.CreatedAt)
	return err
}

func (s *Store) ConfirmEnrollment(ctx context.Context, tenantID string, e *mfa.TOTPEnrollment, codeHashes []string) error {
	if e.TenantID != "" && e.TenantID != tenantID {
		return mfa.ErrTenantMismatch
	}
	e.TenantID = tenantID
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	sealed, err := s.sealSecret(e.Secret, totpAAD(tenantID, e.UserID))
	if err != nil {
		return fmt.Errorf("mfa pgx: sealing secret: %w", err)
	}
	secretStr := base64.StdEncoding.EncodeToString(sealed)

	var lastAttemptAt *time.Time
	if !e.LastAttemptAt.IsZero() {
		t := e.LastAttemptAt.UTC()
		lastAttemptAt = &t
	}

	const totpQuery = `
		INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, user_id) DO UPDATE
		SET secret = EXCLUDED.secret,
		    confirmed_at = EXCLUDED.confirmed_at,
		    last_used_step = EXCLUDED.last_used_step,
		    failed_attempts = EXCLUDED.failed_attempts,
		    last_attempt_at = EXCLUDED.last_attempt_at
	`
	const insertCode = `
		INSERT INTO mfa_recovery_codes (tenant_id, user_id, code_hash, used_at, created_at)
		VALUES ($1, $2, $3, NULL, $4)
	`
	now := time.Now().UTC()

	confirm := func(q DBQuerier) error {
		if _, err := q.Exec(ctx, totpQuery, tenantID, e.UserID, secretStr, e.ConfirmedAt, e.LastUsedStep, e.FailedAttempts, lastAttemptAt, e.CreatedAt); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, e.UserID); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, tenantID, e.UserID); err != nil {
			return err
		}
		for _, h := range codeHashes {
			if _, err := q.Exec(ctx, insertCode, tenantID, e.UserID, h, now); err != nil {
				return err
			}
		}
		return nil
	}

	beginner, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return confirm(s.db)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return err
	}
	if err := confirm(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*mfa.TOTPEnrollment, error) {
	const query = `
		SELECT secret, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at
		FROM mfa_totp
		WHERE tenant_id = $1 AND user_id = $2
	`
	e := &mfa.TOTPEnrollment{UserID: userID, TenantID: tenantID}
	var lastAttemptAt *time.Time
	var secretStr string
	err := s.db.QueryRow(ctx, query, tenantID, userID).Scan(
		&secretStr, &e.ConfirmedAt, &e.LastUsedStep, &e.FailedAttempts, &lastAttemptAt, &e.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mfa.ErrNotEnrolled
		}
		return nil, err
	}

	sealed, err := base64.StdEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("mfa pgx: decoding secret: %w", err)
	}
	plaintext, err := s.openSecret(sealed, totpAAD(tenantID, userID))
	if err != nil {
		return nil, fmt.Errorf("mfa pgx: opening secret: %w", err)
	}
	e.Secret = string(plaintext)

	if lastAttemptAt != nil {
		e.LastAttemptAt = *lastAttemptAt
	}
	return e, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return err
}

func (s *Store) MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error) {
	// A fresh accepted step also clears the failed-attempt budget and decay timestamp (reset on success).
	const query = `
		UPDATE mfa_totp SET last_used_step = $3, failed_attempts = 0, last_attempt_at = NULL
		WHERE tenant_id = $1 AND user_id = $2 AND last_used_step < $3
	`
	tag, err := s.db.Exec(ctx, query, tenantID, userID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) IncrementTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error) {
	increment := func(q DBQuerier) (int, error) {
		var currentAttempts int
		var lastAttemptAt *time.Time
		err := q.QueryRow(ctx, `SELECT failed_attempts, last_attempt_at FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`, tenantID, userID).Scan(&currentAttempts, &lastAttemptAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, mfa.ErrNotEnrolled
			}
			return 0, err
		}

		newAttempts := currentAttempts + 1
		newLastAttempt := now.UTC()

		if maxAttempts > 0 && currentAttempts >= maxAttempts {
			decayed := false
			if lockoutDuration > 0 && lastAttemptAt != nil && now.Sub(*lastAttemptAt) > lockoutDuration {
				decayed = true
			}
			if !decayed {
				// Locked and not decayed: DoS fix: do not increment or bump timestamp,
				// but return an over-limit count so the service knows it's locked.
				return currentAttempts + 1, nil
			}
			newAttempts = 1
		}

		_, err = q.Exec(ctx, `UPDATE mfa_totp SET failed_attempts = $3, last_attempt_at = $4 WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, newAttempts, newLastAttempt)
		if err != nil {
			return 0, err
		}
		return newAttempts, nil
	}

	beginner, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return increment(s.db)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return 0, err
	}
	attempts, err := increment(tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return attempts, nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID, codeHashes []string) error {
	now := time.Now().UTC()
	const insert = `
		INSERT INTO mfa_recovery_codes (tenant_id, user_id, code_hash, used_at, created_at)
		VALUES ($1, $2, $3, NULL, $4)
	`
	// The replace MUST be all-or-nothing (documented atomicity): otherwise a failed INSERT
	// after the DELETE auto-commits would wipe the user's existing recovery codes and leave a
	// partial/empty set. Run DELETE + INSERTs in one transaction.
	replace := func(q DBQuerier) error {
		if _, err := q.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
			return err
		}
		for _, h := range codeHashes {
			if _, err := q.Exec(ctx, insert, tenantID, userID, h, now); err != nil {
				return err
			}
		}
		return nil
	}

	// When db is a pool/conn it can begin a transaction; when it is already a pgx.Tx, Begin
	// opens a savepoint, so this is correct either way.
	beginner, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return replace(s.db)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return err
	}
	if err := replace(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, tenantID string, userID uuid.UUID, codeHash string) error {
	const consume = `
		UPDATE mfa_recovery_codes SET used_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL
	`
	// Resetting the TOTP and recovery-code lock-out budget on a successful consume must commit
	// together with the consume itself; the recovery code (already marked used) is a successful
	// second-factor verification. Run all in one transaction so the budget cannot leak a half-applied state.
	const resetBudget = `
		UPDATE mfa_totp SET failed_attempts = 0, last_attempt_at = NULL
		WHERE tenant_id = $1 AND user_id = $2
	`
	const resetRecovery = `
		UPDATE mfa_recovery_attempts SET failed_attempts = 0, last_attempt_at = NULL
		WHERE tenant_id = $1 AND user_id = $2
	`
	consumeAndReset := func(q DBQuerier) error {
		tag, err := q.Exec(ctx, consume, tenantID, userID, codeHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return mfa.ErrRecoveryCodeNotFound
		}
		// Best-effort reset; no-op when the user has recovery codes but no TOTP enrollment.
		_, _ = q.Exec(ctx, resetBudget, tenantID, userID)
		_, _ = q.Exec(ctx, resetRecovery, tenantID, userID)
		return nil
	}

	beginner, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return consumeAndReset(s.db)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return err
	}
	if err := consumeAndReset(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, tenantID string, userID uuid.UUID) error {
	_, _ = s.db.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return err
}

func (s *Store) IncrementRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID, now time.Time, maxAttempts int, lockoutDuration time.Duration) (int, error) {
	increment := func(q DBQuerier) (int, error) {
		var currentAttempts int
		var lastAttemptAt *time.Time
		err := q.QueryRow(ctx, `SELECT failed_attempts, last_attempt_at FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`, tenantID, userID).Scan(&currentAttempts, &lastAttemptAt)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return 0, err
			}
			currentAttempts = 0
			lastAttemptAt = nil
		}

		newAttempts := currentAttempts + 1
		newLastAttempt := now.UTC()

		if maxAttempts > 0 && currentAttempts >= maxAttempts {
			decayed := false
			if lockoutDuration > 0 && lastAttemptAt != nil && now.Sub(*lastAttemptAt) > lockoutDuration {
				decayed = true
			}
			if !decayed {
				// Locked and not decayed: DoS fix: do not increment or bump timestamp,
				// but return an over-limit count so the service knows it's locked.
				return currentAttempts + 1, nil
			}
			newAttempts = 1
		}

		const upsert = `
			INSERT INTO mfa_recovery_attempts (tenant_id, user_id, failed_attempts, last_attempt_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, user_id) DO UPDATE
			SET failed_attempts = EXCLUDED.failed_attempts,
			    last_attempt_at = EXCLUDED.last_attempt_at
		`
		_, err = q.Exec(ctx, upsert, tenantID, userID, newAttempts, newLastAttempt)
		if err != nil {
			return 0, err
		}
		return newAttempts, nil
	}

	beginner, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return increment(s.db)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return 0, err
	}
	attempts, err := increment(tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return attempts, nil
}

func (s *Store) ResetRecoveryAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error {
	const query = `
		UPDATE mfa_recovery_attempts SET failed_attempts = 0, last_attempt_at = NULL
		WHERE tenant_id = $1 AND user_id = $2
	`
	_, err := s.db.Exec(ctx, query, tenantID, userID)
	return err
}

var _ mfa.Store = (*Store)(nil)

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}

func (s *Store) ResetTOTPAttempts(ctx context.Context, tenantID string, userID uuid.UUID) error {
	const query = `
		UPDATE mfa_totp SET failed_attempts = 0, last_attempt_at = NULL
		WHERE tenant_id = $1 AND user_id = $2
	`
	tag, err := s.db.Exec(ctx, query, tenantID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return mfa.ErrNotEnrolled
	}
	return nil
}
