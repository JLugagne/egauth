package pgx

import (
	"context"
	"embed"
	"errors"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/sessions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the sessions module's Postgres schema,
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

// Store implements sessions.Store for PostgreSQL using pgx.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

// CreateSession persists a new session. If the record carries a non-empty TenantID that
// differs from tenantID, it returns ErrTenantMismatch.
func (s *Store) CreateSession(ctx context.Context, tenantID string, session *sessions.Session) error {
	if session.TenantID != "" && session.TenantID != tenantID {
		return sessions.ErrTenantMismatch
	}
	session.TenantID = tenantID

	query := `
		INSERT INTO sessions (id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, expires_at = EXCLUDED.expires_at
	`
	_, err := s.db.Exec(ctx, query, session.ID, session.TenantID, session.UserID, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.CreatedAt)
	return err
}

// FindSessionByHash retrieves a session by its token hash, scoped to tenantID.
func (s *Store) FindSessionByHash(ctx context.Context, tenantID string, tokenHash string) (*sessions.Session, error) {
	query := `
		SELECT id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at
		FROM sessions
		WHERE token_hash = $1 AND tenant_id = $2
	`

	row := s.db.QueryRow(ctx, query, tokenHash, tenantID)

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

// UpdateSession updates the mutable fields of an existing session (token hash, expiry,
// user-agent, IP) identified by session.ID, as a compare-and-set on expectedTokenHash. The ID,
// tenant, UserID and CreatedAt are immutable — the UPDATE never writes those columns. Re-binding a
// session to a different user is the job of BindSession.
func (s *Store) UpdateSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	query := `
		UPDATE sessions
		SET token_hash = $1, user_agent = $2, ip = $3, expires_at = $4
		WHERE id = $5 AND tenant_id = $6 AND token_hash = $7
	`
	tag, err := s.db.Exec(ctx, query, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.ID, tenantID, expectedTokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Unknown id/tenant, or the token was already rotated away by a concurrent request.
		return sessions.ErrSessionNotFound
	}
	return nil
}

// BindSession atomically re-binds an existing session to a new UserID while rotating its token,
// identified by session.ID and gated by a compare-and-set on expectedTokenHash. It is the
// anonymous-to-authenticated upgrade primitive. The UPDATE writes user_id alongside the mutable
// fields; id, tenant_id and created_at are never written.
func (s *Store) BindSession(ctx context.Context, tenantID string, session *sessions.Session, expectedTokenHash string) error {
	query := `
		UPDATE sessions
		SET user_id = $1, token_hash = $2, user_agent = $3, ip = $4, expires_at = $5
		WHERE id = $6 AND tenant_id = $7 AND token_hash = $8
	`
	tag, err := s.db.Exec(ctx, query, session.UserID, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.ID, tenantID, expectedTokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Unknown id/tenant, or the token was already rotated away by a concurrent request.
		return sessions.ErrSessionNotFound
	}
	return nil
}

// DeleteSession removes a session by its ID within the given tenant.
func (s *Store) DeleteSession(ctx context.Context, tenantID string, id uuid.UUID) error {
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

// DeleteExpired purges sessions past their expiry within the given tenant, returning the number deleted.
func (s *Store) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < now() AND tenant_id = $1`
	tag, err := s.db.Exec(ctx, query, tenantID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteSessionsByUserID removes all sessions for a user within the given tenant.
func (s *Store) DeleteSessionsByUserID(ctx context.Context, tenantID string, userID uuid.UUID) error {
	query := `DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2`
	_, err := s.db.Exec(ctx, query, userID, tenantID)
	return err
}

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
