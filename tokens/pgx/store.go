package pgx

import (
	"context"
	"database/sql/driver"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

// Migrate executes all the embedded SQL migrations against the provided DBQuerier.
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

func (s *Store[C]) getTenantID(opts []tokens.Option) string {
	options := tokens.ApplyOptions(opts)
	if options.TenantID == nil {
		return ""
	}
	return *options.TenantID
}

// SaveRefreshToken persists the hash of a refresh token.
func (s *Store[C]) SaveRefreshToken(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error {
	tenantID := s.getTenantID(opts)

	query := `
		INSERT INTO tokens (tenant_id, token_hash, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at
	`
	_, err := s.db.Exec(ctx, query, tenantID, tokenHash, userID, expiresAt, time.Now().UTC())
	return err
}

// FindRefreshTokenByHash retrieves a refresh token hash information.
func (s *Store[C]) FindRefreshTokenByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (uuid.UUID, time.Time, error) {
	tenantID := s.getTenantID(opts)

	query := `
		SELECT user_id, expires_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var userID uuid.UUID
	var expiresAt time.Time
	err := row.Scan(&userID, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, time.Time{}, tokens.ErrRefreshTokenNotFound
		}
		return uuid.Nil, time.Time{}, err
	}

	return userID, expiresAt, nil
}

// RevokeRefreshToken marks a refresh token as revoked or deletes it.
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	tenantID := s.getTenantID(opts)

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

// SaveAPIKey persists an API key.
func (s *Store[C]) SaveAPIKey(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error {
	tenantID := s.getTenantID(opts)
	if tenantID != "" {
		key.TenantID = tenantID
	}

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
	tenantID := s.getTenantID(opts)

	query := `
		SELECT id, tenant_id, token_hash, user_id, prefix, claims, expires_at
		FROM tokens
		WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NOT NULL
	`
	row := s.db.QueryRow(ctx, query, tenantID, tokenHash)

	var key tokens.APIKey[C]
	var claimsJSON []byte
	err := row.Scan(&key.ID, &key.TenantID, &key.Hash, &key.Claims.Subject, &key.Prefix, &claimsJSON, &key.ExpiresAt)
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
