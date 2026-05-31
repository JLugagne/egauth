package pgx

import (
	"context"
	"embed"
	"errors"

	"github.com/JLugagne/libauth/internal/pgxmigrate"
	"github.com/JLugagne/libauth/sessions"
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

// Store implements sessions.Store for PostgreSQL using pgx.
type Store struct {
	db     DBQuerier
	strict bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (sessions.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid
// default single-tenant partition. The "effective" tenant is the one from WithTenant, or, for
// CreateSession, the tenant carried on the session itself; strict mode rejects only when that
// effective tenant is empty. (DeleteExpired is exempt: it is a maintenance sweep that
// intentionally spans all tenants when no tenant is given.)
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new PostgreSQL store.
func NewStore(db DBQuerier, opts ...Option) *Store {
	s := &Store{db: db}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant resolves the operation tenant (WithTenant takes precedence over fallback, the
// tenant carried on the record) and enforces ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(fallback string, opts []sessions.Option) (string, error) {
	o := sessions.ApplyOptions(opts)
	tenant := fallback
	if o.TenantID != nil {
		tenant = *o.TenantID
	}
	if s.strict && tenant == "" {
		return "", sessions.ErrTenantRequired
	}
	return tenant, nil
}

// CreateSession persists a new session.
func (s *Store) CreateSession(ctx context.Context, session *sessions.Session, opts ...sessions.Option) error {
	tenantID, err := s.resolveTenant(session.TenantID, opts)
	if err != nil {
		return err
	}
	session.TenantID = tenantID

	query := `
		INSERT INTO sessions (id, tenant_id, user_id, token_hash, user_agent, ip, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, token_hash) DO UPDATE
		SET id = EXCLUDED.id, user_id = EXCLUDED.user_id, user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, expires_at = EXCLUDED.expires_at
	`
	_, err = s.db.Exec(ctx, query, session.ID, session.TenantID, session.UserID, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.CreatedAt)
	return err
}

// FindSessionByHash retrieves a session by its token hash.
func (s *Store) FindSessionByHash(ctx context.Context, tokenHash string, opts ...sessions.Option) (*sessions.Session, error) {
	options := sessions.ApplyOptions(opts)
	// A nil tenant means "match any tenant" (no scoping). Strict mode forbids that unscoped
	// lookup, and an explicit empty tenant, so a forgotten WithTenant fails loudly.
	if s.strict && (options.TenantID == nil || *options.TenantID == "") {
		return nil, sessions.ErrTenantRequired
	}

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

// UpdateSession updates the mutable fields of an existing session (token hash, expiry,
// user-agent, IP) identified by session.ID, as a compare-and-set on expectedTokenHash. The ID
// and tenant are immutable.
func (s *Store) UpdateSession(ctx context.Context, session *sessions.Session, expectedTokenHash string, opts ...sessions.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

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

// DeleteSession removes a session by its ID.
func (s *Store) DeleteSession(ctx context.Context, id uuid.UUID, opts ...sessions.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

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

// DeleteExpired purges sessions past their expiry, returning the number deleted. With WithTenant
// it sweeps a single tenant, otherwise all.
func (s *Store) DeleteExpired(ctx context.Context, opts ...sessions.Option) (int64, error) {
	options := sessions.ApplyOptions(opts)

	query := `DELETE FROM sessions WHERE expires_at < now()`
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

// DeleteSessionsByUserID removes all sessions for a user.
func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, opts ...sessions.Option) error {
	tenantID, err := s.resolveTenant("", opts)
	if err != nil {
		return err
	}

	query := `DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2`
	_, err = s.db.Exec(ctx, query, userID, tenantID)
	return err
}

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
