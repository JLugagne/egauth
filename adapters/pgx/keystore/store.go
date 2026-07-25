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
	return pgxmigrate.Run(ctx, db, MigrationsFS, "keystore")
}

// DBQuerier matches both *pgxpool.Pool and pgx.Tx.
type DBQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store implements keystore.Store for PostgreSQL using pgx.
//
// Tenant records live in keystore_tenants, independent of the key rows in keystore_keys, so the
// backend can honor the keystore.Store sentinel contract: a tenant whose keys were revoked still
// exists (ErrNoActiveKey), and only DeleteTenant makes it unknown (ErrTenantNotFound). See
// migration 003 for why that distinction is security-relevant.
type Store struct {
	db DBQuerier
	// now is the time source used to evaluate key activity and expiry. It is the APPLICATION
	// clock, deliberately not the database clock, so a Store agrees with the keystore.Manager that
	// stamped NotAfter (and with a test clock).
	now func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the Store's time source, which decides whether a key row still counts as
// active or verifiable. It must be the same clock the keystore.Manager is built with, so both
// layers agree on expiry. The default is time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// NewStore creates a new PostgreSQL keystore Store.
func NewStore(db DBQuerier, opts ...Option) *Store {
	s := &Store{db: db, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ keystore.Store = (*Store)(nil)

// CreateTenant records a new tenant with its initial signing key. It returns
// keystore.ErrTenantExists if the tenant already has key material.
func (s *Store) CreateTenant(ctx context.Context, tenantID string, initial keystore.SigningKey) error {
	if err := guardTenant(tenantID, initial); err != nil {
		return err
	}
	beginner, ok := s.db.(txBeginner)
	if !ok {
		return s.createTenantChecked(ctx, s, tenantID, initial)
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, tenantID); err != nil {
		return err
	}
	if err := s.createTenantChecked(ctx, &Store{db: tx, now: s.now}, tenantID, initial); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TenantExists reports whether the tenant record exists. It is deliberately independent of the
// tenant's key rows: a tenant whose keys were revoked still exists until DeleteTenant.
func (s *Store) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	var dummy int
	err := s.db.QueryRow(ctx,
		`SELECT 1 FROM keystore_tenants WHERE tenant_id = $1`, tenantID).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PutSigningKey inserts or replaces a key for the tenant, creating the tenant record when absent.
func (s *Store) PutSigningKey(ctx context.Context, tenantID string, key keystore.SigningKey) error {
	if err := guardTenant(tenantID, key); err != nil {
		return err
	}
	if _, err := s.insertTenant(ctx, tenantID); err != nil {
		return err
	}
	query := `
		INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at, not_after, retired_at, alg)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at,
			not_after = EXCLUDED.not_after, retired_at = EXCLUDED.retired_at, alg = EXCLUDED.alg
	`
	_, err := s.db.Exec(ctx, query, tenantID, key.KeyID, key.Secret,
		key.CreatedAt, nullTime(key.NotAfter), key.RetiredAt, algOrDefault(key.Alg))
	return err
}

// ActiveSigningKey returns the tenant's newest active key (not retired, not past not_after). It
// returns keystore.ErrNoActiveKey when the tenant exists but holds no active key (for example after
// RevokeTenantKeys) and keystore.ErrTenantNotFound only when the tenant record is absent.
func (s *Store) ActiveSigningKey(ctx context.Context, tenantID string) (keystore.SigningKey, error) {
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return keystore.SigningKey{}, err
	}
	if !exists {
		return keystore.SigningKey{}, keystore.ErrTenantNotFound
	}
	query := `
		SELECT key_id, secret, created_at, not_after, retired_at, alg
		FROM keystore_keys
		WHERE tenant_id = $1
		  AND retired_at IS NULL
		  AND (not_after IS NULL OR not_after > $2)
		ORDER BY created_at DESC
		LIMIT 1
	`
	key, err := scanKey(s.db.QueryRow(ctx, query, tenantID, s.now()), tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return keystore.SigningKey{}, keystore.ErrNoActiveKey
		}
		return keystore.SigningKey{}, err
	}
	return key, nil
}

// VerificationKeys returns every key that may still verify a token (not past not_after), keyed
// by key id. For an existing tenant with no usable key it returns an empty map and a nil error (so
// a JWKS endpoint publishes an empty set after a revoke); keystore.ErrTenantNotFound is reserved
// for an absent tenant record.
func (s *Store) VerificationKeys(ctx context.Context, tenantID string) (map[string]keystore.SigningKey, error) {
	exists, err := s.TenantExists(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, keystore.ErrTenantNotFound
	}
	query := `
		SELECT key_id, secret, created_at, not_after, retired_at, alg
		FROM keystore_keys
		WHERE tenant_id = $1 AND (not_after IS NULL OR not_after > $2)
	`
	rows, err := s.db.Query(ctx, query, tenantID, s.now())
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
			WHERE tenant_id = $1 AND retired_at IS NULL AND (not_after IS NULL OR not_after > $9)
		)
		INSERT INTO keystore_keys (tenant_id, key_id, secret, created_at, not_after, retired_at, alg)
		VALUES ($1, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at,
			not_after = EXCLUDED.not_after, retired_at = EXCLUDED.retired_at, alg = EXCLUDED.alg
	`
	if _, err := s.insertTenant(ctx, tenantID); err != nil {
		return err
	}
	next.TenantID = tenantID
	_, err := s.db.Exec(ctx, query, tenantID, retiredAt, next.KeyID, next.Secret, next.CreatedAt, nullTime(next.NotAfter), next.RetiredAt, algOrDefault(next.Alg), s.now())
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

// RevokeTenantKeys immediately deletes every key for the tenant, leaving no key material. The
// TENANT RECORD SURVIVES so the revocation holds: subsequent resolutions report
// keystore.ErrNoActiveKey, which a lazily-provisioning Manager does not treat as an invitation to
// mint a replacement key.
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

// DeleteTenant removes the tenant record and all its keys. Deleting an absent tenant is a no-op
// success.
func (s *Store) DeleteTenant(ctx context.Context, tenantID string) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM keystore_keys WHERE tenant_id = $1`, tenantID); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM keystore_tenants WHERE tenant_id = $1`, tenantID)
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
		alg       string
	)
	if err := r.Scan(&k.KeyID, &k.Secret, &k.CreatedAt, &notAfter, &retiredAt, &alg); err != nil {
		return keystore.SigningKey{}, err
	}
	k.TenantID = tenantID
	if notAfter != nil {
		k.NotAfter = *notAfter
	}
	k.RetiredAt = retiredAt
	k.Alg = alg
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

// algOrDefault maps an empty Alg to "HS256" so a key minted before the alg field existed persists
// as HS256 rather than an empty string.
func algOrDefault(a string) string {
	if a == "" {
		return "HS256"
	}
	return a
}

// createTenantChecked claims the tenant record and installs its initial key. The claim is the
// INSERT itself (the primary key decides the winner), so two concurrent creates cannot both proceed
// even without the advisory lock.
func (s *Store) createTenantChecked(ctx context.Context, q *Store, tenantID string, initial keystore.SigningKey) error {
	inserted, err := q.insertTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if !inserted {
		return keystore.ErrTenantExists
	}
	initial.TenantID = tenantID
	return q.PutSigningKey(ctx, tenantID, initial)
}

// insertTenant records the tenant if it is not already known, reporting whether this call created
// it.
func (s *Store) insertTenant(ctx context.Context, tenantID string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`INSERT INTO keystore_tenants (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}
