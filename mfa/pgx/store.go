// Package pgx provides a PostgreSQL-backed mfa.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/libauth/mfa"
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

// Store implements mfa.Store for PostgreSQL.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL mfa store.
func NewStore(db DBQuerier) *Store { return &Store{db: db} }

func (s *Store) tenantID(opts []mfa.Option) string {
	o := mfa.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
}

func (s *Store) SaveTOTP(ctx context.Context, e *mfa.TOTPEnrollment, opts ...mfa.Option) error {
	tenant := s.tenantID(opts)
	if tenant == "" {
		return mfa.ErrTenantRequired
	}
	e.TenantID = tenant
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
	_, err := s.db.Exec(ctx, query, tenant, e.UserID, e.Secret, e.ConfirmedAt, e.LastUsedStep, e.CreatedAt)
	return err
}

func (s *Store) GetTOTP(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) (*mfa.TOTPEnrollment, error) {
	tenant := s.tenantID(opts)
	const query = `
		SELECT secret, confirmed_at, last_used_step, created_at
		FROM mfa_totp
		WHERE tenant_id = $1 AND user_id = $2
	`
	e := &mfa.TOTPEnrollment{UserID: userID, TenantID: tenant}
	err := s.db.QueryRow(ctx, query, tenant, userID).Scan(&e.Secret, &e.ConfirmedAt, &e.LastUsedStep, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mfa.ErrNotEnrolled
		}
		return nil, err
	}
	return e, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) error {
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`, s.tenantID(opts), userID)
	return err
}

func (s *Store) MarkTOTPUsed(ctx context.Context, userID uuid.UUID, step int64, opts ...mfa.Option) (bool, error) {
	const query = `
		UPDATE mfa_totp SET last_used_step = $3
		WHERE tenant_id = $1 AND user_id = $2 AND last_used_step < $3
	`
	tag, err := s.db.Exec(ctx, query, s.tenantID(opts), userID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string, opts ...mfa.Option) error {
	tenant := s.tenantID(opts)
	if tenant == "" {
		return mfa.ErrTenantRequired
	}

	now := time.Now().UTC()
	const insert = `
		INSERT INTO mfa_recovery_codes (tenant_id, user_id, code_hash, used_at, created_at)
		VALUES ($1, $2, $3, NULL, $4)
	`
	// The replace MUST be all-or-nothing (documented atomicity): otherwise a failed INSERT
	// after the DELETE auto-commits would wipe the user's existing recovery codes and leave a
	// partial/empty set. Run DELETE + INSERTs in one transaction.
	replace := func(q DBQuerier) error {
		if _, err := q.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenant, userID); err != nil {
			return err
		}
		for _, h := range codeHashes {
			if _, err := q.Exec(ctx, insert, tenant, userID, h, now); err != nil {
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

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string, opts ...mfa.Option) error {
	const query = `
		UPDATE mfa_recovery_codes SET used_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, s.tenantID(opts), userID, codeHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return mfa.ErrRecoveryCodeNotFound
	}
	return nil
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, userID uuid.UUID, opts ...mfa.Option) error {
	_, err := s.db.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, s.tenantID(opts), userID)
	return err
}

var _ mfa.Store = (*Store)(nil)
