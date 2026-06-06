// Package pgx provides a PostgreSQL-backed passkey.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/passkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the passkey module's Postgres schema,
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

// Store implements passkey.Store for PostgreSQL.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL passkey store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

// SaveCredential persists a newly registered credential. If c.TenantID is non-empty and
// differs from tenantID, it returns ErrTenantMismatch; otherwise it sets c.TenantID = tenantID.
func (s *Store) SaveCredential(ctx context.Context, tenantID string, c *passkey.Credential) error {
	if c.TenantID != "" && c.TenantID != tenantID {
		return passkey.ErrTenantMismatch
	}
	c.TenantID = tenantID
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	const query = `
		INSERT INTO passkey_credentials (tenant_id, user_id, credential_id, public_key, sign_count, data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.Exec(ctx, query, tenantID, c.UserID, c.ID, c.PublicKey, int64(c.SignCount), c.Data, c.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation on (tenant_id, credential_id)
		return passkey.ErrCredentialExists
	}
	return err
}

// GetCredentials returns all credentials registered by the user (empty slice if none).
func (s *Store) GetCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*passkey.Credential, error) {
	const query = `
		SELECT credential_id, public_key, sign_count, data, created_at
		FROM passkey_credentials
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at
	`
	rows, err := s.db.Query(ctx, query, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*passkey.Credential
	for rows.Next() {
		c := &passkey.Credential{UserID: userID, TenantID: tenantID}
		var signCount int64
		if err := rows.Scan(&c.ID, &c.PublicKey, &signCount, &c.Data, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCredential persists changes to an existing credential (notably the signature counter
// after a successful login). Returns ErrCredentialNotFound if absent.
func (s *Store) UpdateCredential(ctx context.Context, tenantID string, c *passkey.Credential) error {
	const query = `
		UPDATE passkey_credentials
		SET public_key = $4, sign_count = $5, data = $6
		WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3
	`
	tag, err := s.db.Exec(ctx, query, tenantID, c.UserID, c.ID, c.PublicKey, int64(c.SignCount), c.Data)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

// DeleteCredential removes one of the user's credentials by its credential ID. Returns
// ErrCredentialNotFound if absent.
func (s *Store) DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error {
	const query = `DELETE FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3`
	tag, err := s.db.Exec(ctx, query, tenantID, userID, credentialID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

var _ passkey.Store = (*Store)(nil)

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
