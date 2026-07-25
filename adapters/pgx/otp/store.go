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
	return pgxmigrate.Run(ctx, db, MigrationsFS, "otp")
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

	const query = `
		INSERT INTO otp_codes (tenant_id, subject_id, purpose, code_hash, attempts, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
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
