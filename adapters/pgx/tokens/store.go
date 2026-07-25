package pgx

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the tokens module's Postgres schema,
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

// DBQuerier is an interface that matches both *pgxpool.Pool and pgx.Tx.
type DBQuerier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store implements tokens.Store for PostgreSQL using pgx.
type Store[C any] struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL store.
func NewStore[C any](db DBQuerier) *Store[C] {
	return &Store[C]{db: db}
}

// SaveRefreshToken persists a refresh token record (storing only its hash).
func (s *Store[C]) SaveRefreshToken(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
	if rt.TenantID != "" && rt.TenantID != tenantID {
		return tokens.ErrTenantMismatch
	}

	createdAt := rt.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	// auth_time is stored as NULL when unset so legacy rows and callers that do not track it
	// scan back to a zero time. family_created_at follows the same convention, defaulting to this
	// row's created_at so a row saved without an explicit anchor still caps its family.
	var authTime *time.Time
	if !rt.AuthTime.IsZero() {
		authTime = &rt.AuthTime
	}
	familyCreatedAt := rt.FamilyCreatedAt
	if familyCreatedAt.IsZero() {
		familyCreatedAt = createdAt
	}
	var kind *string
	if rt.Kind != "" {
		k := string(rt.Kind)
		kind = &k
	}

	query := `
		INSERT INTO tokens (tenant_id, token_hash, user_id, family_id, auth_time, kind, must_change_password, expires_at, created_at, family_created_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET user_id = EXCLUDED.user_id, family_id = EXCLUDED.family_id, auth_time = EXCLUDED.auth_time,
			kind = EXCLUDED.kind, must_change_password = EXCLUDED.must_change_password,
			expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at,
			family_created_at = EXCLUDED.family_created_at, consumed_at = EXCLUDED.consumed_at
	`
	_, err := s.db.Exec(ctx, query, tenantID, rt.Hash, rt.UserID, rt.FamilyID, authTime, kind, rt.MustChangePassword, rt.ExpiresAt, createdAt, familyCreatedAt, rt.ConsumedAt)
	return err
}

// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
func (s *Store[C]) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	query := `
		SELECT token_hash, family_id, user_id, tenant_id, auth_time, kind, must_change_password, expires_at, created_at, family_created_at, consumed_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var rt tokens.RefreshToken
	var authTime *time.Time
	var kind *string
	var familyCreatedAt *time.Time
	err := row.Scan(&rt.Hash, &rt.FamilyID, &rt.UserID, &rt.TenantID, &authTime, &kind, &rt.MustChangePassword, &rt.ExpiresAt, &rt.CreatedAt, &familyCreatedAt, &rt.ConsumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, tokens.ErrRefreshTokenNotFound
		}
		return nil, err
	}
	if authTime != nil {
		rt.AuthTime = *authTime
	}
	if kind != nil {
		rt.Kind = egauth.PrincipalKind(*kind)
	}
	if familyCreatedAt != nil {
		rt.FamilyCreatedAt = *familyCreatedAt
	}

	return &rt, nil
}

// ConsumeRefreshToken atomically marks a refresh token as consumed (single-use).
func (s *Store[C]) ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
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
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
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

// DeleteExpired purges expired token rows (refresh tokens and any API keys past their expiry)
// within the given tenant, returning the number deleted. Rows with a NULL expires_at
// (never-expiring API keys) are kept.
func (s *Store[C]) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	query := `DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < now() AND tenant_id = $1`
	tag, err := s.db.Exec(ctx, query, tenantID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
func (s *Store[C]) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	query := `DELETE FROM tokens WHERE tenant_id = $1 AND family_id = $2 AND claims IS NULL`
	_, err := s.db.Exec(ctx, query, tenantID, familyID)
	return err
}

// RevokeAllRefreshTokensForUser revokes EVERY refresh token belonging to userID within tenantID,
// across all families. Refresh-token rows are identified by claims IS NULL. Idempotent: zero
// matching rows returns nil (never ErrRefreshTokenNotFound).
func (s *Store[C]) RevokeAllRefreshTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	query := `DELETE FROM tokens WHERE tenant_id = $1 AND user_id = $2 AND claims IS NULL`
	_, err := s.db.Exec(ctx, query, tenantID, userID)
	return err
}

// SaveAPIKey persists an API key, including its type and created_by fields.
func (s *Store[C]) SaveAPIKey(ctx context.Context, tenantID string, key *tokens.APIKey[C]) error {
	if key.TenantID != "" && key.TenantID != tenantID {
		return tokens.ErrTenantMismatch
	}
	key.TenantID = tenantID

	claimsJSON, err := json.Marshal(key.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Resolve the key type; default to service when not set (safe, restricted default).
	keyType := key.Type
	if keyType == "" {
		keyType = tokens.KeyTypeService
	}

	// created_by is nullable: store nil when the zero UUID is supplied so the column stays NULL.
	var createdBy *uuid.UUID
	if key.CreatedBy != uuid.Nil {
		createdBy = &key.CreatedBy
	}

	query := `
		INSERT INTO tokens (id, tenant_id, token_hash, user_id, prefix, claims, expires_at, created_at, type, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, prefix = EXCLUDED.prefix,
			claims = EXCLUDED.claims, expires_at = EXCLUDED.expires_at,
			type = EXCLUDED.type, created_by = EXCLUDED.created_by
	`
	_, err = s.db.Exec(ctx, query,
		key.ID, key.TenantID, key.Hash, key.Claims.Subject, key.Prefix,
		claimsJSON, key.ExpiresAt, time.Now().UTC(),
		string(keyType), createdBy,
	)
	return err
}

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store[C]) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}

// FindAPIKeyByHash retrieves an API key by its hash, including revoked_at so callers can
// distinguish active keys from revoked ones. Revoked keys are returned (not filtered); the
// verify layer maps a non-nil RevokedAt to ErrAPIKeyRevoked.
func (s *Store[C]) FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[C], error) {
	query := `
		SELECT id, tenant_id, token_hash, user_id, prefix, claims, expires_at, type, created_by, revoked_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NOT NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var key tokens.APIKey[C]
	var claimsJSON []byte
	var keyType string
	var createdBy *uuid.UUID
	err := row.Scan(&key.ID, &key.TenantID, &key.Hash, &key.Claims.Subject, &key.Prefix, &claimsJSON, &key.ExpiresAt, &keyType, &createdBy, &key.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, tokens.ErrAPIKeyNotFound
		}
		return nil, err
	}

	key.Type = tokens.KeyType(keyType)
	if createdBy != nil {
		key.CreatedBy = *createdBy
	}

	if err := json.Unmarshal(claimsJSON, &key.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return &key, nil
}

// RevokeAPIKey soft-revokes the key identified by keyID within the given tenant by setting
// revoked_at = now(). The update is conditional on revoked_at IS NULL so it is idempotent:
//   - 0 rows updated AND the key does not exist at all → ErrAPIKeyNotFound
//   - 0 rows updated AND the key already has revoked_at set → no-op success (idempotent)
//   - 1 row updated → success
func (s *Store[C]) RevokeAPIKey(ctx context.Context, tenantID string, keyID uuid.UUID) error {
	updateQuery := `
		UPDATE tokens
		SET revoked_at = now()
		WHERE id = $1 AND tenant_id = $2 AND claims IS NOT NULL AND revoked_at IS NULL
	`
	tag, err := s.db.Exec(ctx, updateQuery, keyID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// No row updated: either the key doesn't exist or it was already revoked.
		// Distinguish the two cases with an existence check.
		existsQuery := `
			SELECT 1 FROM tokens
			WHERE id = $1 AND tenant_id = $2 AND claims IS NOT NULL
		`
		var dummy int
		err := s.db.QueryRow(ctx, existsQuery, keyID, tenantID).Scan(&dummy)
		if errors.Is(err, pgx.ErrNoRows) {
			return tokens.ErrAPIKeyNotFound
		}
		if err != nil {
			return err
		}
		// Key exists but was already revoked — idempotent no-op.
	}
	return nil
}

// RevokeAllAPIKeysForUser soft-revokes EVERY active API key created by userID within tenantID by
// stamping revoked_at = now() on rows where revoked_at IS NULL. API-key rows are identified by
// claims IS NOT NULL. Already-revoked keys are left untouched (their original revoked_at stands).
// Idempotent: zero matching rows returns nil (never ErrAPIKeyNotFound).
func (s *Store[C]) RevokeAllAPIKeysForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	query := `
		UPDATE tokens
		SET revoked_at = now()
		WHERE tenant_id = $1 AND created_by = $2 AND claims IS NOT NULL AND revoked_at IS NULL
	`
	_, err := s.db.Exec(ctx, query, tenantID, userID)
	return err
}

// ListAPIKeysByCreator returns all API keys created by the given user within the tenant.
// Revoked keys are included (with RevokedAt populated). Token (clear-text) is never populated.
// An unknown creator returns an empty, non-nil slice with no error.
func (s *Store[C]) ListAPIKeysByCreator(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*tokens.APIKey[C], error) {
	query := `
		SELECT id, tenant_id, token_hash, user_id, prefix, claims, expires_at, type, created_by, revoked_at
		FROM tokens
		WHERE tenant_id = $1 AND created_by = $2 AND claims IS NOT NULL
		ORDER BY created_at ASC
	`
	rows, err := s.db.Query(ctx, query, tenantID, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]*tokens.APIKey[C], 0)
	for rows.Next() {
		var key tokens.APIKey[C]
		var claimsJSON []byte
		var keyType string
		var createdByPtr *uuid.UUID
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Hash, &key.Claims.Subject, &key.Prefix, &claimsJSON, &key.ExpiresAt, &keyType, &createdByPtr, &key.RevokedAt); err != nil {
			return nil, err
		}
		key.Type = tokens.KeyType(keyType)
		if createdByPtr != nil {
			key.CreatedBy = *createdByPtr
		}
		if err := json.Unmarshal(claimsJSON, &key.Claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
		}
		result = append(result, &key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
