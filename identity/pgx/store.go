package pgx

import (
	"context"
	"embed"
	"errors"
	"strings"
	"time"

	"github.com/JLugagne/libauth/identity"
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

// Store implements identity.Store for PostgreSQL using pgx.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
}

func (s *Store) getTenantID(opts []identity.Option) string {
	options := identity.ApplyOptions(opts)
	if options.TenantID == nil {
		return ""
	}
	return *options.TenantID
}

func mapError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" { // Unique violation
			if strings.Contains(pgErr.ConstraintName, "users_email_tenant") {
				return identity.ErrEmailAlreadyExists
			}
			if strings.Contains(pgErr.ConstraintName, "identities_provider_tenant") {
				return identity.ErrIdentityAlreadyExists
			}
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// Specific mapping for not found happens in the caller based on context
		return err
	}
	return err
}

func (s *Store) CreateUser(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	tenantID := s.getTenantID(opts)
	if tenantID == "" {
		return nil, identity.ErrTenantRequired
	}

	user := &identity.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     email,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	query := `
		INSERT INTO users (id, tenant_id, email, email_verified_at, created_at, updated_at, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.Exec(ctx, query, user.ID, user.TenantID, user.Email, user.EmailVerifiedAt, user.CreatedAt, user.UpdatedAt, user.DeletedAt)
	if err != nil {
		return nil, mapError(err)
	}

	return user, nil
}

func (s *Store) FindUserByID(ctx context.Context, id uuid.UUID, opts ...identity.Option) (*identity.User, error) {
	tenantID := s.getTenantID(opts)
	query := `
		SELECT id, tenant_id, email, email_verified_at, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND tenant_id = $2
	`
	row := s.db.QueryRow(ctx, query, id, tenantID)

	var user identity.User
	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &user.EmailVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	tenantID := s.getTenantID(opts)
	query := `
		SELECT id, tenant_id, email, email_verified_at, created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`
	row := s.db.QueryRow(ctx, query, email, tenantID)

	var user identity.User
	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &user.EmailVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (s *Store) UpdateUser(ctx context.Context, user *identity.User, opts ...identity.Option) error {
	tenantID := s.getTenantID(opts)
	if tenantID == "" {
		return identity.ErrTenantRequired
	}

	user.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE users
		SET email = $1, email_verified_at = $2, updated_at = $3
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, user.Email, user.EmailVerifiedAt, user.UpdatedAt, user.ID, tenantID)
	if err != nil {
		return mapError(err)
	}

	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}

	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID, opts ...identity.Option) error {
	tenantID := s.getTenantID(opts)

	// Soft delete and anonymize email
	now := time.Now().UTC()
	anonymizedEmail := "deleted_" + uuid.New().String() + "@deleted.local"

	query := `
		UPDATE users
		SET deleted_at = $1, email = $2, updated_at = $1
		WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
	`
	_, err := s.db.Exec(ctx, query, now, anonymizedEmail, id, tenantID)
	if err != nil {
		return err
	}

	identQuery := `
		UPDATE identities
		SET provider_id = $1, updated_at = $2
		WHERE user_id = $3 AND tenant_id = $4
	`
	_, err = s.db.Exec(ctx, identQuery, anonymizedEmail, now, id, tenantID)
	return err
}

func (s *Store) AddIdentity(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error {
	tenantID := s.getTenantID(opts)
	if tenantID == "" {
		return identity.ErrTenantRequired
	}

	ident.ID = uuid.New()
	ident.TenantID = tenantID
	ident.CreatedAt = time.Now().UTC()
	ident.UpdatedAt = time.Now().UTC()

	query := `
		INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.db.Exec(ctx, query, ident.ID, ident.UserID, ident.TenantID, ident.Provider, ident.ProviderID, ident.PasswordHash, ident.CreatedAt, ident.UpdatedAt)
	if err != nil {
		return mapError(err)
	}

	return nil
}

func (s *Store) FindIdentitiesByUserID(ctx context.Context, userID uuid.UUID, opts ...identity.Option) ([]*identity.Identity, error) {
	tenantID := s.getTenantID(opts)

	query := `
		SELECT id, user_id, tenant_id, provider, provider_id, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM identities
		WHERE user_id = $1 AND tenant_id = $2
	`
	rows, err := s.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []*identity.Identity
	for rows.Next() {
		var ident identity.Identity
		if err := rows.Scan(&ident.ID, &ident.UserID, &ident.TenantID, &ident.Provider, &ident.ProviderID, &ident.PasswordHash, &ident.FailedAttempts, &ident.LockedUntil, &ident.CreatedAt, &ident.UpdatedAt); err != nil {
			return nil, err
		}
		identities = append(identities, &ident)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return identities, nil
}

func (s *Store) FindIdentityByProvider(ctx context.Context, provider, providerID string, opts ...identity.Option) (*identity.Identity, error) {
	tenantID := s.getTenantID(opts)

	query := `
		SELECT id, user_id, tenant_id, provider, provider_id, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM identities
		WHERE provider = $1 AND provider_id = $2 AND tenant_id = $3
	`
	row := s.db.QueryRow(ctx, query, provider, providerID, tenantID)

	var ident identity.Identity
	err := row.Scan(&ident.ID, &ident.UserID, &ident.TenantID, &ident.Provider, &ident.ProviderID, &ident.PasswordHash, &ident.FailedAttempts, &ident.LockedUntil, &ident.CreatedAt, &ident.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrIdentityNotFound
		}
		return nil, err
	}

	return &ident, nil
}

// IncrementFailedAttempts increments the failed-attempt counter for an identity,
// locking the account when the new count reaches the threshold. It is performed
// atomically in a single UPDATE statement.
func (s *Store) IncrementFailedAttempts(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error {
	tenantID := s.getTenantID(opts)

	query := `
		UPDATE identities
		SET failed_attempts = failed_attempts + 1,
			locked_until = CASE
				WHEN failed_attempts + 1 >= $3 THEN now() + ($4::bigint * interval '1 millisecond')
				ELSE locked_until
			END,
			updated_at = now()
		WHERE id = $1 AND tenant_id = $2
	`
	tag, err := s.db.Exec(ctx, query, identityID, tenantID, lockThreshold, lockDuration.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrIdentityNotFound
	}
	return nil
}

// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
func (s *Store) ResetFailedAttempts(ctx context.Context, identityID uuid.UUID, opts ...identity.Option) error {
	tenantID := s.getTenantID(opts)

	query := `
		UPDATE identities
		SET failed_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1 AND tenant_id = $2
	`
	tag, err := s.db.Exec(ctx, query, identityID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrIdentityNotFound
	}
	return nil
}
