// Package pgx provides a PostgreSQL-backed passkey.Store using jackc/pgx.
package pgx

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/libauth/passkey"
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

// Store implements passkey.Store for PostgreSQL.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL passkey store.
func NewStore(db DBQuerier) *Store { return &Store{db: db} }

func (s *Store) tenantID(opts []passkey.Option) string {
	o := passkey.ApplyOptions(opts)
	if o.TenantID == nil {
		return ""
	}
	return *o.TenantID
}

func (s *Store) SaveCredential(ctx context.Context, c *passkey.Credential, opts ...passkey.Option) error {
	tenant := s.tenantID(opts)
	if tenant == "" {
		return passkey.ErrTenantRequired
	}
	c.TenantID = tenant
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	const query = `
		INSERT INTO passkey_credentials (tenant_id, user_id, credential_id, public_key, sign_count, data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.Exec(ctx, query, tenant, c.UserID, c.ID, c.PublicKey, int64(c.SignCount), c.Data, c.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation on (tenant_id, credential_id)
		return passkey.ErrCredentialExists
	}
	return err
}

func (s *Store) GetCredentials(ctx context.Context, userID uuid.UUID, opts ...passkey.Option) ([]*passkey.Credential, error) {
	tenant := s.tenantID(opts)
	const query = `
		SELECT credential_id, public_key, sign_count, data, created_at
		FROM passkey_credentials
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at
	`
	rows, err := s.db.Query(ctx, query, tenant, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*passkey.Credential
	for rows.Next() {
		c := &passkey.Credential{UserID: userID, TenantID: tenant}
		var signCount int64
		if err := rows.Scan(&c.ID, &c.PublicKey, &signCount, &c.Data, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpdateCredential(ctx context.Context, c *passkey.Credential, opts ...passkey.Option) error {
	const query = `
		UPDATE passkey_credentials
		SET public_key = $4, sign_count = $5, data = $6
		WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3
	`
	tag, err := s.db.Exec(ctx, query, s.tenantID(opts), c.UserID, c.ID, c.PublicKey, int64(c.SignCount), c.Data)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

func (s *Store) DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte, opts ...passkey.Option) error {
	const query = `DELETE FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3`
	tag, err := s.db.Exec(ctx, query, s.tenantID(opts), userID, credentialID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

var _ passkey.Store = (*Store)(nil)
