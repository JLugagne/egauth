package pgx

import (
	"context"
	"database/sql/driver"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/libauth/internal/pgxmigrate"
	"github.com/JLugagne/libauth/tokens"
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

// DBQuerier is an interface that matches both *pgxpool.Pool and pgx.Tx.
type DBQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store implements tokens.Store for PostgreSQL using pgx.
type Store[C any] struct {
	db     DBQuerier
	strict bool
}

// storeOptions accumulates Store-construction options. It is intentionally non-generic so callers
// write NewStore[C](pool, WithStrictTenancy()) rather than spelling the type parameter on the option.
type storeOptions struct{ strict bool }

// Option configures a Store.
type Option func(*storeOptions)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (tokens.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid
// default single-tenant partition. The "effective" tenant is the one from WithTenant, or, for
// the Save* operations, the tenant carried on the record itself; strict mode rejects only when
// that effective tenant is empty. (DeleteExpired is exempt: it is a maintenance sweep that
// intentionally spans all tenants when no tenant is given.)
func WithStrictTenancy() Option { return func(o *storeOptions) { o.strict = true } }

// NewStore creates a new PostgreSQL store.
func NewStore[C any](db DBQuerier, opts ...Option) *Store[C] {
	var o storeOptions
	for _, opt := range opts {
		opt(&o)
	}
	return &Store[C]{db: db, strict: o.strict}
}

// resolveTenant resolves the operation tenant (WithTenant takes precedence over fallback, the
// tenant carried on the record) and enforces ErrTenantRequired in strict mode.
func (s *Store[C]) resolveTenant(fallback string, opts []tokens.Option) (string, error) {
	o := tokens.ApplyOptions(opts)
	tenant := fallback
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", tokens.ErrTenantRequired
	}
	return tenant, nil
}

// SaveRefreshToken persists a refresh token record (storing only its hash).
func (s *Store[C]) SaveRefreshToken(ctx context.Context, rt *tokens.RefreshToken, opts ...tokens.Option) error {
	tenantID, err := s.resolveTenant(rt.TenantID, opts)
	if err != nil {
		return err
	}

	createdAt := rt.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	// auth_time is stored as NULL when unset so legacy rows and callers that do not track it
	// scan back to a zero time.
	var authTime *time.Time
	if !rt.AuthTime.IsZero() {
		authTime = &rt.AuthTime
	}

	query := `
		INSERT INTO tokens (tenant_id, token_hash, user_id, family_id, auth_time, expires_at, created_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET user_id = EXCLUDED.user_id, family_id = EXCLUDED.family_id, auth_time = EXCLUDED.auth_time,
			expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at, consumed_at = EXCLUDED.consumed_at
	`
	_, err = s.db.Exec(ctx, query, tenantID, rt.Hash, rt.UserID, rt.FamilyID, authTime, rt.ExpiresAt, createdAt, rt.ConsumedAt)
	return err
}

// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
func (s *Store[C]) FindRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.RefreshToken, error) {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT token_hash, family_id, user_id, tenant_id, auth_time, expires_at, created_at, consumed_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var rt tokens.RefreshToken
	var authTime *time.Time
	err = row.Scan(&rt.Hash, &rt.FamilyID, &rt.UserID, &rt.TenantID, &authTime, &rt.ExpiresAt, &rt.CreatedAt, &rt.ConsumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, tokens.ErrRefreshTokenNotFound
		}
		return nil, err
	}
	if authTime != nil {
		rt.AuthTime = *authTime
	}

	return &rt, nil
}

// ConsumeRefreshToken atomically marks a refresh token as consumed (single-use).
func (s *Store[C]) ConsumeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

	query := `
		UPDATE tokens SET consumed_at = now()
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL AND consumed_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, tenantID, tokenHash)
	if err != nil {
		return err
	}

	if tag.RowsAffected() > 0 {
		return nil
	}

	// 0 rows: either the token does not exist (in this tenant) or it was already consumed.
	// Disambiguate with an existence check to return the correct sentinel.
	existsQuery := `SELECT 1 FROM tokens WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL`
	var dummy int
	err = s.db.QueryRow(ctx, existsQuery, tenantID, tokenHash).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tokens.ErrRefreshTokenNotFound
		}
		return err
	}

	// The token exists but already had consumed_at set -> replay.
	return tokens.ErrRefreshTokenReused
}

// RevokeRefreshToken deletes/revokes a single refresh token by its hash.
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

	query := `DELETE FROM tokens WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL`
	tag, err := s.db.Exec(ctx, query, tenantID, tokenHash)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return tokens.ErrRefreshTokenNotFound
	}

	return nil
}

// DeleteExpired purges expired token rows (refresh tokens and any API keys past their expiry),
// returning the number deleted. Rows with a NULL expires_at (never-expiring API keys) are kept.
// With WithTenant it sweeps a single tenant, otherwise all.
func (s *Store[C]) DeleteExpired(ctx context.Context, opts ...tokens.Option) (int64, error) {
	options := tokens.ApplyOptions(opts)

	query := `DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < now()`
	args := []any{}
	if options.TenantID != nil {
		query += ` AND tenant_id = $1`
		args = append(args, *options.TenantID)
	}

	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
func (s *Store[C]) RevokeFamily(ctx context.Context, familyID uuid.UUID, opts ...tokens.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

	query := `DELETE FROM tokens WHERE tenant_id = $1 AND family_id = $2 AND claims IS NULL`
	_, err = s.db.Exec(ctx, query, tenantID, familyID)
	return err
}

// SaveAPIKey persists an API key.
func (s *Store[C]) SaveAPIKey(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error {
	tenantID, err := s.resolveTenant(key.TenantID, opts)
	if err != nil {
		return err
	}
	key.TenantID = tenantID

	claimsJSON, err := json.Marshal(key.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	query := `
		INSERT INTO tokens (id, tenant_id, token_hash, user_id, prefix, claims, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, prefix = EXCLUDED.prefix, claims = EXCLUDED.claims, expires_at = EXCLUDED.expires_at
	`
	_, err = s.db.Exec(ctx, query, key.ID, key.TenantID, key.Hash, key.Claims.Subject, key.Prefix, claimsJSON, key.ExpiresAt, time.Now().UTC())
	return err
}

// FindAPIKeyByHash retrieves an API key by its hash.
func (s *Store[C]) FindAPIKeyByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[C], error) {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, tenant_id, token_hash, user_id, prefix, claims, expires_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NOT NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var key tokens.APIKey[C]
	var claimsJSON []byte
	err = row.Scan(&key.ID, &key.TenantID, &key.Hash, &key.Claims.Subject, &key.Prefix, &claimsJSON, &key.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, tokens.ErrAPIKeyNotFound
		}
		return nil, err
	}

	if err := json.Unmarshal(claimsJSON, &key.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return &key, nil
}

// jsonbWrapper is not strictly needed if we marshal manually as above,
// but it's good practice for complex types.
// Given the generic Store[C], we handle it in Scan/Value if we want to use row.Scan directly into a struct field.

type claimsWrapper[C any] struct {
	Claims *tokens.Claims[C]
}

func (w claimsWrapper[C]) Value() (driver.Value, error) {
	if w.Claims == nil {
		return nil, nil
	}
	return json.Marshal(w.Claims)
}

func (w *claimsWrapper[C]) Scan(value any) error {
	if value == nil {
		w.Claims = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, &w.Claims)
}

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store[C]) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
