// Package keystore is the PostgreSQL (pgx) backend for github.com/JLugagne/egauth/keystore.
// It persists per-tenant signing keys — with their secrets already KEK-sealed by the
// keystore.Manager — so a database dump never yields usable signing material on its own.
//
// Run Migrate once at startup to create the schema, then wire NewStore into a keystore.Manager.
package keystore

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/keystore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the keystore Postgres schema, applied via
// Migrate (which runs them through pgxmigrate).
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

// Store implements keystore.Store for PostgreSQL using pgx.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL keystore Store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

var _ keystore.Store = (*Store)(nil)

// CreateTenant records a new tenant with its initial signing key. It returns
// keystore.ErrTenantExists if the tenant already has key material.
func (s *Store) CreateTenant(ctx context.Context, tenantID string, initial keystore.SigningKey) error {
	if err := guardTenant(tenantID, initial); err != nil {
		return err
	}
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return err
	}
	if exists {
		return keystore.ErrTenantExists
	}
	initial.TenantID = tenantID
	return s.PutSigningKey(ctx, tenantID, initial)
}

// TenantExists reports whether the tenant has any key material.
func (s *Store) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	var dummy int
	err := s.db.QueryRow(ctx,
		`SELECT 1 FROM keystore_keys WHERE tenant_id = $1 LIMIT 1`, tenantID).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PutSigningKey inserts or replaces a key for the tenant.
func (s *Store) PutSigningKey(ctx context.Context, tenantID string, key keystore.SigningKey) error {
	if err := guardTenant(tenantID, key); err != nil {
		return err
	}
	query := `
		INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at, not_after, retired_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at,
			not_after = EXCLUDED.not_after, retired_at = EXCLUDED.retired_at
	`
	_, err := s.db.Exec(ctx, query, tenantID, key.KeyID, key.Secret,
		key.CreatedAt, nullTime(key.NotAfter), key.RetiredAt)
	return err
}

// ActiveSigningKey returns the tenant's newest active key (not retired, not past not_after).
func (s *Store) ActiveSigningKey(ctx context.Context, tenantID string) (keystore.SigningKey, error) {
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return keystore.SigningKey{}, err
	}
	if !exists {
		return keystore.SigningKey{}, keystore.ErrTenantNotFound
	}
	query := `
		SELECT key_id, secret, created_at, not_after, retired_at
		FROM keystore_keys
		WHERE tenant_id = $1
		  AND retired_at IS NULL
		  AND (not_after IS NULL OR not_after > now())
		ORDER BY created_at DESC
		LIMIT 1
	`
	key, err := scanKey(s.db.QueryRow(ctx, query, tenantID), tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return keystore.SigningKey{}, keystore.ErrNoActiveKey
		}
		return keystore.SigningKey{}, err
	}
	return key, nil
}

// VerificationKeys returns every key that may still verify a token (not past not_after), keyed
// by key id.
func (s *Store) VerificationKeys(ctx context.Context, tenantID string) (map[string]keystore.SigningKey, error) {
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, keystore.ErrTenantNotFound
	}
	query := `
		SELECT key_id, secret, created_at, not_after, retired_at
		FROM keystore_keys
		WHERE tenant_id = $1 AND (not_after IS NULL OR not_after > now())
	`
	rows, err := s.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]keystore.SigningKey{}
	for rows.Next() {
		key, err := scanKey(rows, tenantID)
		if err != nil {
			return nil, err
		}
		out[key.KeyID] = key
	}
	return out, rows.Err()
}

// RotateSigningKey installs next and retires every currently-active key (verify-only), capping
// their not_after at retiredAt so RetireExpiredKeys reaps them after the overlap. It runs in a
// single transaction for atomicity.
func (s *Store) RotateSigningKey(ctx context.Context, tenantID string, next keystore.SigningKey, retiredAt time.Time) error {
	if err := guardTenant(tenantID, next); err != nil {
		return err
	}
	query := `
		WITH retired AS (
			UPDATE keystore_keys
			SET retired_at = $2,
				not_after = CASE
					WHEN not_after IS NULL OR not_after > $2 THEN $2
					ELSE not_after
				END
			WHERE tenant_id = $1 AND retired_at IS NULL AND (not_after IS NULL OR not_after > now())
		)
		INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at, not_after, retired_at)
		VALUES ($1, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at,
			not_after = EXCLUDED.not_after, retired_at = EXCLUDED.retired_at
	`
	next.TenantID = tenantID
	_, err := s.db.Exec(ctx, query, tenantID, retiredAt, next.KeyID, next.Secret, next.CreatedAt, nullTime(next.NotAfter), next.RetiredAt)
	return err
}

// RetireExpiredKeys deletes keys whose not_after is at or before now, returning the count
// removed. It never removes a key still active.
func (s *Store) RetireExpiredKeys(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	query := `
		DELETE FROM keystore_keys
		WHERE tenant_id = $1 AND not_after IS NOT NULL AND not_after <= $2
	`
	tag, err := s.db.Exec(ctx, query, tenantID, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeTenantKeys immediately deletes every key for the tenant (leaving no key material).
func (s *Store) RevokeTenantKeys(ctx context.Context, tenantID string) error {
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return err
	}
	if !exists {
		return keystore.ErrTenantNotFound
	}
	_, err = s.db.Exec(ctx, `DELETE FROM keystore_keys WHERE tenant_id = $1`, tenantID)
	return err
}

// DeleteTenant removes the tenant and all its keys. Deleting an absent tenant is a no-op success.
func (s *Store) DeleteTenant(ctx context.Context, tenantID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM keystore_keys WHERE tenant_id = $1`, tenantID)
	return err
}

// Ping verifies connectivity by issuing a trivial query.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanKey scans one keystore_keys row into a keystore.SigningKey.
func scanKey(r rowScanner, tenantID string) (keystore.SigningKey, error) {
	var (
		k         keystore.SigningKey
		notAfter  *time.Time
		retiredAt *time.Time
	)
	if err := r.Scan(&k.KeyID, &k.Secret, &k.CreatedAt, &notAfter, &retiredAt); err != nil {
		return keystore.SigningKey{}, err
	}
	k.TenantID = tenantID
	if notAfter != nil {
		k.NotAfter = *notAfter
	}
	k.RetiredAt = retiredAt
	return k, nil
}

// nullTime maps a zero time.Time to NULL for the not_after column.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// guardTenant fails closed when a key's embedded TenantID contradicts the operation's tenantID.
func guardTenant(tenantID string, key keystore.SigningKey) error {
	if key.TenantID != "" && key.TenantID != tenantID {
		return keystore.ErrTenantMismatch
	}
	return nil
}
