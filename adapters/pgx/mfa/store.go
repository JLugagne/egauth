// Package pgx provides a PostgreSQL-backed mfa.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/keystore"
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

// KEK provides envelope encryption for TOTP secrets at rest. It is satisfied by
// *keystore.KEK. Every call names the SecretContext the blob belongs to, so a sealed TOTP secret
// cannot be opened as another tenant's, another user's, or another subsystem's secret.
type KEK interface {
	Seal(sc keystore.SecretContext, plaintext []byte) ([]byte, error)
	Open(sc keystore.SecretContext, sealed []byte) ([]byte, error)
}

// TOTPSecretContext returns the SecretContext a user's TOTP shared secret is sealed under: the
// tenant, the mfa/totp-secret purpose, and the row's own identity (its user id). Operators
// re-sealing existing rows in place must reproduce it exactly — see keystore.SecretContext.
func TOTPSecretContext(tenantID string, userID uuid.UUID) keystore.SecretContext {
	return keystore.SecretContext{
		TenantID: tenantID,
		Purpose:  keystore.PurposeTOTPSecret,
		RowID:    userID.String(),
	}
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

	sealed, err := s.kek.Seal(TOTPSecretContext(tenantID, e.UserID), []byte(e.Secret))
	if err != nil {
		return errors.Join(errors.New("mfa pgx: sealing secret"), err)
	}
	secretStr := base64.StdEncoding.EncodeToString(sealed)

	_, err = s.db.Exec(ctx, query, tenantID, e.UserID, secretStr, e.ConfirmedAt, e.LastUsedStep, e.FailedAttempts, lastAttemptAt, e.CreatedAt)
	return err
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
		return nil, errors.Join(errors.New("mfa pgx: decoding secret"), err)
	}
	plaintext, err := s.kek.Open(TOTPSecretContext(tenantID, userID), sealed)
	if err != nil {
		return nil, errors.Join(errors.New("mfa pgx: opening secret"), err)
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
	// Resetting the TOTP lock-out budget on a successful consume must commit together with the
	// consume itself; the recovery code (already marked used) is a successful second-factor
	// verification. Run both in one transaction so the budget cannot leak a half-applied state.
	const resetBudget = `
		UPDATE mfa_totp SET failed_attempts = 0, last_attempt_at = NULL
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
		_, err = q.Exec(ctx, resetBudget, tenantID, userID)
		return err
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
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
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
