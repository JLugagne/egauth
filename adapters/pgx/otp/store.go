// Package pgx provides a PostgreSQL-backed otp.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/otp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the otp module's Postgres schema,
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

// Store implements otp.Store for PostgreSQL.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL OTP store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

func (s *Store) SaveOTP(ctx context.Context, tenantID string, o *otp.OTP) error {
	if o.TenantID != "" && o.TenantID != tenantID {
		return otp.ErrTenantMismatch
	}
	o.TenantID = tenantID
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}

	// The issuance tombstone (otp_issuances.last_issued_at) is recorded in the SAME statement as
	// the code upsert, so a later IssueOTP enforces the resend cooldown from o.CreatedAt even after
	// this code is consumed, burned, deleted or expired (F-OTP-001). Writing the issuance row
	// first also keeps a single lock order (issuances, then codes) shared with IssueOTP.
	const query = `
		WITH issued AS (
			INSERT INTO otp_issuances (tenant_id, subject_id, purpose, last_issued_at)
			VALUES ($1, $2, $3, $7)
			ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
			SET last_issued_at = EXCLUDED.last_issued_at
			RETURNING 1
		)
		INSERT INTO otp_codes (tenant_id, subject_id, purpose, code_hash, attempts, expires_at, created_at)
		SELECT $1, $2, $3, $4, $5, $6, $7 FROM issued
		ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
		SET code_hash = EXCLUDED.code_hash,
		    attempts = EXCLUDED.attempts,
		    expires_at = EXCLUDED.expires_at,
		    created_at = EXCLUDED.created_at
	`
	_, err := s.db.Exec(ctx, query, tenantID, o.SubjectID, o.Purpose, o.CodeHash, o.Attempts, o.ExpiresAt, o.CreatedAt)
	return err
}

func (s *Store) GetOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (*otp.OTP, error) {
	const query = `
		SELECT code_hash, attempts, expires_at, created_at
		FROM otp_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
	`
	o := &otp.OTP{SubjectID: subjectID, TenantID: tenantID, Purpose: purpose}
	err := s.db.QueryRow(ctx, query, tenantID, subjectID, purpose).Scan(&o.CodeHash, &o.Attempts, &o.ExpiresAt, &o.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, otp.ErrCodeNotFound
		}
		return nil, err
	}
	return o, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) (int, error) {
	const query = `
		UPDATE otp_codes SET attempts = attempts + 1
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
		RETURNING attempts
	`
	var attempts int
	err := s.db.QueryRow(ctx, query, tenantID, subjectID, purpose).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, otp.ErrCodeNotFound
		}
		return 0, err
	}
	return attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, expectedCodeHash string) (bool, error) {
	// Identity guard: the code_hash predicate makes this a compare-and-delete. A code reissued
	// between the verifier's read and this consume carries a different hash and is not deleted,
	// so a superseded code cannot burn its replacement.
	tag, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3 AND code_hash = $4`, tenantID, subjectID, purpose, expectedCodeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) DeleteOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3`, tenantID, subjectID, purpose)
	return err
}

// DeleteExpired purges codes past their expiry within the given tenant, returning the number deleted.
func (s *Store) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE expires_at < now() AND tenant_id = $1`, tenantID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

var _ otp.Store = (*Store)(nil)

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}

// IssueOTP atomically enforces the resend cooldown and upserts o as the new outstanding code.
//
// The cooldown is measured against a durable issuance tombstone in otp_issuances — a row separate
// from otp_codes, so consuming, burning, deleting or expiring the code never resets the throttle —
// and the check + upsert run in ONE statement, so concurrent issue requests serialise on the
// issuance row lock: exactly one passes and the rest observe ErrCooldownActive (F-OTP-002).
// cooldown <= 0 disables the check. `last_issued_at <= o.CreatedAt - cooldown` is the admit
// condition, so a stored instant after o.CreatedAt (clock skew) is refused too. If the record
// carries a non-empty TenantID that differs from tenantID the call is rejected before any write.
func (s *Store) IssueOTP(ctx context.Context, tenantID string, o *otp.OTP, cooldown time.Duration) error {
	if o.TenantID != "" && o.TenantID != tenantID {
		return otp.ErrTenantMismatch
	}
	o.TenantID = tenantID
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}

	disabled := cooldown <= 0
	threshold := o.CreatedAt
	if !disabled {
		threshold = o.CreatedAt.Add(-cooldown)
	}

	// The issuance CTE always runs; when the cooldown is active and the admission predicate is
	// false it updates nothing and returns no row, so the code INSERT below selects nothing and
	// stores nothing. Only the caller that wins the issuance row lock inserts the code.
	const query = `
		WITH issued AS (
			INSERT INTO otp_issuances (tenant_id, subject_id, purpose, last_issued_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
			SET last_issued_at = EXCLUDED.last_issued_at
			WHERE $5::boolean OR otp_issuances.last_issued_at <= $6::timestamptz
			RETURNING 1
		)
		INSERT INTO otp_codes (tenant_id, subject_id, purpose, code_hash, attempts, expires_at, created_at)
		SELECT $1, $2, $3, $7, $8, $9, $4 FROM issued
		ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
		SET code_hash = EXCLUDED.code_hash,
		    attempts = EXCLUDED.attempts,
		    expires_at = EXCLUDED.expires_at,
		    created_at = EXCLUDED.created_at
		RETURNING 1
	`
	var one int
	err := s.db.QueryRow(ctx, query, tenantID, o.SubjectID, o.Purpose, o.CreatedAt, disabled, threshold, o.CodeHash, o.Attempts, o.ExpiresAt).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return otp.ErrCooldownActive
		}
		return err
	}
	return nil
}
