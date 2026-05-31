// Package pgx provides a PostgreSQL-backed otp.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/libauth/internal/pgxmigrate"
	"github.com/JLugagne/libauth/otp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

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
	db     DBQuerier
	strict bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every operation require a non-empty tenant (ErrTenantRequired
// otherwise). Off by default, where an empty tenant is the default single-tenant partition.
// Enable it in multi-tenant deployments so a forgotten WithTenant fails loudly instead of
// silently operating on the shared empty-tenant partition. (DeleteExpired is exempt: it is a
// maintenance sweep that intentionally spans all tenants when no tenant is given.)
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new PostgreSQL OTP store.
func NewStore(db DBQuerier, opts ...Option) *Store {
	s := &Store{db: db}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant extracts the operation tenant, enforcing ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(opts []otp.Option) (string, error) {
	o := otp.ApplyOptions(opts)
	tenant := ""
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", otp.ErrTenantRequired
	}
	return tenant, nil
}

func (s *Store) SaveOTP(ctx context.Context, o *otp.OTP, opts ...otp.Option) error {
	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
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
	_, err = s.db.Exec(ctx, query, tenant, o.SubjectID, o.Purpose, o.CodeHash, o.Attempts, o.ExpiresAt, o.CreatedAt)
	return err
}

func (s *Store) GetOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (*otp.OTP, error) {
	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
	}
	const query = `
		SELECT code_hash, attempts, expires_at, created_at
		FROM otp_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
	`
	o := &otp.OTP{SubjectID: subjectID, TenantID: tenant, Purpose: purpose}
	err = s.db.QueryRow(ctx, query, tenant, subjectID, purpose).Scan(&o.CodeHash, &o.Attempts, &o.ExpiresAt, &o.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, otp.ErrCodeNotFound
		}
		return nil, err
	}
	return o, nil
}

func (s *Store) IncrementOTPAttempts(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (int, error) {
	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return 0, err
	}
	const query = `
		UPDATE otp_codes SET attempts = attempts + 1
		WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3
		RETURNING attempts
	`
	var attempts int
	err = s.db.QueryRow(ctx, query, tenant, subjectID, purpose).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, otp.ErrCodeNotFound
		}
		return 0, err
	}
	return attempts, nil
}

func (s *Store) ConsumeOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) (bool, error) {
	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return false, err
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3`, tenant, subjectID, purpose)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) DeleteOTP(ctx context.Context, subjectID uuid.UUID, purpose string, opts ...otp.Option) error {
	tenant, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM otp_codes WHERE tenant_id = $1 AND subject_id = $2 AND purpose = $3`, tenant, subjectID, purpose)
	return err
}

// DeleteExpired purges codes past their expiry, returning the number deleted. With WithTenant it
// sweeps a single tenant, otherwise all (a cross-tenant maintenance sweep).
func (s *Store) DeleteExpired(ctx context.Context, opts ...otp.Option) (int64, error) {
	o := otp.ApplyOptions(opts)
	query := `DELETE FROM otp_codes WHERE expires_at < now()`
	args := []any{}
	if o.TenantID != nil {
		query += ` AND tenant_id = $1`
		args = append(args, *o.TenantID)
	}
	tag, err := s.db.Exec(ctx, query, args...)
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
