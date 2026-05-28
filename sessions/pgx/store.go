package pgx

import (
	"context"
	"embed"
	"errors"

	"github.com/JLugagne/libauth/sessions"
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

// Store implements sessions.Store for PostgreSQL using pgx.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

func (s *Store) getTenantID(opts []sessions.Option) string {
	options := sessions.ApplyOptions(opts)
	if options.TenantID == nil {
		return ""
	}
	return *options.TenantID
}

// CreateSession persists a new session.
func (s *Store) CreateSession(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error {
	tenantID := s.getTenantID(opts)
	if tenantID != "" {
		session.TenantID = tenantID
	}

	query := `
		INSERT INTO sessions (id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, expires_at = EXCLUDED.expires_at
	`
	_, err := s.db.Exec(ctx, query, session.ID, session.TenantID, session.UserID, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.CreatedAt)
	return err
}

// FindSessionByHash retrieves a session by its token hash.
func (s *Store) FindSessionByHash(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error) {
	options := sessions.ApplyOptions(opts)

	query := `
		SELECT id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at
		FROM sessions
		WHERE token_hash = $1
	`
	args := []any{tokenHash}
	if options.TenantID != nil {
		query += " AND tenant_id = $2"
		args = append(args, *options.TenantID)
	}

	row := s.db.QueryRow(ctx, query, args...)

	var sess sessions.Session
	err := row.Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.TokenHash, &sess.UserAgent, &sess.IP, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, sessions.ErrSessionNotFound
		}
		return nil, err
	}

	return &sess, nil
}

// DeleteSession removes a session by its ID.
func (s *Store) DeleteSession(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error {
	tenantID := s.getTenantID(opts)

	query := `DELETE FROM sessions WHERE id = $1 AND tenant_id = $2`
	tag, err := s.db.Exec(ctx, query, id, tenantID)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return sessions.ErrSessionNotFound
	}

	return nil
}

// DeleteSessionsByUserID removes all sessions for a user.
func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error {
	tenantID := s.getTenantID(opts)

	query := `DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2`
	_, err := s.db.Exec(ctx, query, userID, tenantID)
	return err
}
