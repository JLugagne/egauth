// Package pgx provides a PostgreSQL-backed otp.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/libauth/otp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

// Migrate executes all embedded SQL migrations against db.
func Migrate(ctx context.Context, db DBQuerier) error {
	entries, err := MigrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		content, err := MigrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err := db.Exec(ctx, string(content)); err != nil {
			return err
		}
	}
	return nil
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
func NewStore(db DBQuerier) *Store { return &Store{db: db} }

func (s *Store) tenantID(opts []otp.Option) string {
	o := otp.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
}

func (s *Store) SaveOTP(ctx context.Context, o *otp.OTP, opts ...otp.Option) error {
	tenant := s.tenantID(opts)
	if tenant == "" {
		return otp.ErrTenantRequired
	}
	o.TenantID = tenant
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
	_, err := s.db.Exec(ctx, query, tenant, o.SubjectID, o.Purpose, o.CodeHash, o.Attempts, o.ExpiresAt, o.CreatedAt)
	return err
}

func (s *Store) GetOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (*otp.OTP, error) {
	tenant := s.tenantID(opts)
	const query = `
		SELECT code_hash, attempts, expires_at, created_at
		FROM otp_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
	`
	o := &otp.OTP{SubjectID: subjectID, TenantID: tenant, Purpose: purpose}
	err := s.db.QueryRow(ctx, query, tenant, subjectID, purpose).Scan(&o.CodeHash, &o.Attempts, &o.ExpiresAt, &o.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, otp.ErrCodeNotFound
		}
		return nil, err
	}
	return o, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (int, error) {
	const query = `
		UPDATE otp_codes SET attempts = attempts + 1
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
		RETURNING attempts
	`
	var attempts int
	err := s.db.QueryRow(ctx, query, s.tenantID(opts), subjectID, purpose).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, otp.ErrCodeNotFound
		}
		return 0, err
	}
	return attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (bool, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3`, s.tenantID(opts), subjectID, purpose)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) DeleteOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) error {
	_, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3`, s.tenantID(opts), subjectID, purpose)
	return err
}

var _ otp.Store = (*Store)(nil)
