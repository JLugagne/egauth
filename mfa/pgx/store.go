// Package pgx provides a PostgreSQL-backed mfa.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/egauth/internal/pgxmigrate"
	"github.com/JLugagne/egauth/mfa"
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

// Store implements mfa.Store for PostgreSQL.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL mfa store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
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
		INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, user_id) DO UPDATE
		SET secret = EXCLUDED.secret,
		    confirmed_at = EXCLUDED.confirmed_at,
		    last_used_step = EXCLUDED.last_used_step
	`
	_, err := s.db.Exec(ctx, query, tenantID, e.UserID, e.Secret, e.ConfirmedAt, e.LastUsedStep, e.CreatedAt)
	return err
}

func (s *Store) GetTOTP(ctx context.Context, tenantID string, userID uuid.UUID) (*mfa.TOTPEnrollment, error) {
	const query = `
		SELECT secret, confirmed_at, last_used_step, created_at
		FROM mfa_totp
		WHERE tenant_id = $1 AND user_id = $2
	`
	e := &mfa.TOTPEnrollment{UserID: userID, TenantID: tenantID}
	err := s.db.QueryRow(ctx, query, tenantID, userID).Scan(&e.Secret, &e.ConfirmedAt, &e.LastUsedStep, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mfa.ErrNotEnrolled
		}
		return nil, err
	}
	return e, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, tenantID string, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return err
}

func (s *Store) MarkTOTPUsed(ctx context.Context, tenantID string, userID uuid.UUID, step int64) (bool, error) {
	const query = `
		UPDATE mfa_totp SET last_used_step = $3
		WHERE tenant_id = $1 AND user_id = $2 AND last_used_step < $3
	`
	tag, err := s.db.Exec(ctx, query, tenantID, userID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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
	const query = `
		UPDATE mfa_recovery_codes SET used_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, tenantID, userID, codeHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return mfa.ErrRecoveryCodeNotFound
	}
	return nil
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
