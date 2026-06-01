package pgx

import (
	"context"
	"embed"
	"errors"
	"strings"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/pgxmigrate"
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

// Store implements identity.Store for PostgreSQL using pgx.
type Store struct {
	db DBQuerier
}

// NewStore creates a new PostgreSQL store.
func NewStore(db DBQuerier) *Store {
	return &Store{db: db}
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

func (s *Store) CreateUser(ctx context.Context, tenantID string, email string) (*identity.User, error) {
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

func (s *Store) FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
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

func (s *Store) FindUserByEmail(ctx context.Context, tenantID string, email string) (*identity.User, error) {
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

func (s *Store) UpdateUser(ctx context.Context, tenantID string, user *identity.User) error {
	if user.TenantID != "" && user.TenantID != tenantID {
		return identity.ErrTenantMismatch
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

// UpdateUserEmail atomically swaps a live user's email and re-keys its password identity in a
// single statement (data-modifying CTEs share one snapshot and one transaction), so a unique
// violation on either index aborts the whole change.
func (s *Store) UpdateUserEmail(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error {
	now := time.Now().UTC()
	const query = `
		WITH target AS (
			SELECT id FROM users
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		),
		pw AS (
			UPDATE identities
			SET provider_id = $3, updated_at = $4
			WHERE user_id = (SELECT id FROM target) AND tenant_id = $2 AND provider = 'password'
		)
		UPDATE users
		SET email = $3, email_verified_at = $5, updated_at = $4
		WHERE id = (SELECT id FROM target)
	`
	tag, err := s.db.Exec(ctx, query, userID, tenantID, newEmail, now, verifiedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// A conflict on either the user-email index or the password identity index during an
			// email change both mean the new address is already taken in this tenant.
			return identity.ErrEmailAlreadyExists
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// DeleteUser soft-deletes and anonymizes a live user in one atomic statement: it anonymizes the
// users row (deleted_at + random email), anonymizes the user's identity provider_ids, and purges
// any pending verification tokens (which would otherwise outlive the account carrying its user_id
// and, for change-email tokens, a plaintext target email — residual PII the soft delete is meant
// to erase). All three run as data-modifying CTEs gated on the user actually being live, so they
// commit together or not at all. Returns ErrUserNotFound when no live, same-tenant user matches.
func (s *Store) DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	now := time.Now().UTC()
	anonymizedEmail := "deleted_" + uuid.New().String() + "@deleted.local"

	const query = `
		WITH del AS (
			UPDATE users
			SET deleted_at = $1, email = $2, updated_at = $1
			WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
			RETURNING id
		),
		ident AS (
			UPDATE identities
			SET provider_id = $2, updated_at = $1
			WHERE user_id IN (SELECT id FROM del) AND tenant_id = $4
		),
		toks AS (
			DELETE FROM verification_tokens
			WHERE user_id IN (SELECT id FROM del) AND tenant_id = $4
		)
		SELECT id FROM del
	`
	var deletedID uuid.UUID
	err := s.db.QueryRow(ctx, query, now, anonymizedEmail, id, tenantID).Scan(&deletedID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No live, same-tenant user matched, so nothing was deleted.
			return identity.ErrUserNotFound
		}
		return err
	}
	return nil
}

func (s *Store) AddIdentity(ctx context.Context, tenantID string, ident *identity.Identity) error {
	if ident.TenantID != "" && ident.TenantID != tenantID {
		return identity.ErrTenantMismatch
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

func (s *Store) FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error) {
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

func (s *Store) FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
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

// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
// atomically clears any lockout.
func (s *Store) UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string) error {
	query := `
		UPDATE identities
		SET password_hash = $1, failed_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE user_id = $2 AND tenant_id = $3 AND provider = 'password'
	`
	tag, err := s.db.Exec(ctx, query, passwordHash, userID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrIdentityNotFound
	}
	return nil
}

// CreateVerificationToken mints, persists and returns a single-use plaintext token. Only the
// selector and the verifier hash are stored. The INSERT is gated on the target being a LIVE
// user in the SAME tenant (the bare user_id foreign key alone would accept a cross-tenant or
// soft-deleted user), so this matches the memory store's invariant exactly.
func (s *Store) CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error) {
	token, selector, verifierHash, err := identity.GenerateVerificationToken()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	// Explicit casts are required: $3 and $4 appear both in the SELECT list (untyped there)
	// and in the EXISTS comparison, so without casts Postgres cannot deduce their types.
	query := `
		INSERT INTO verification_tokens (selector, verifier_hash, user_id, tenant_id, kind, metadata, expires_at, created_at)
		SELECT $1::varchar, $2::varchar, $3::uuid, $4::varchar, $5::varchar, $6::bytea, $7::timestamptz, $8::timestamptz
		WHERE EXISTS (SELECT 1 FROM users WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL)
	`
	tag, err := s.db.Exec(ctx, query, selector, verifierHash, userID, tenantID, kind, metadata, now.Add(ttl), now)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		// No live, same-tenant user matched the EXISTS guard.
		return "", identity.ErrUserNotFound
	}

	return token, nil
}

// ConsumeVerificationToken validates and atomically consumes a verification token. It looks
// the row up by selector (an indexed, high-entropy key), compares the verifier in constant
// time, checks expiry, then deletes the row with a guarded DELETE so concurrent consumers
// cannot both succeed (single-use).
func (s *Store) ConsumeVerificationToken(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error) {
	selector, verifier, ok := identity.SplitVerificationToken(token)
	if !ok {
		return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
	}

	const selectQuery = `
		SELECT verifier_hash, user_id, metadata, expires_at
		FROM verification_tokens
		WHERE selector = $1 AND tenant_id = $2 AND kind = $3
	`
	var (
		verifierHash string
		userID       uuid.UUID
		metadata     []byte
		expiresAt    time.Time
	)
	err := s.db.QueryRow(ctx, selectQuery, selector, tenantID, kind).Scan(&verifierHash, &userID, &metadata, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
		}
		return uuid.Nil, nil, err
	}

	// Constant-time verifier comparison; a mismatch is reported as "not found" so it is
	// indistinguishable from an unknown selector.
	if !identity.CompareVerifier(verifierHash, verifier) {
		return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
	}

	if time.Now().After(expiresAt) {
		// Expired but genuine: best-effort delete and report expiry to the legitimate holder.
		_, _ = s.db.Exec(ctx, `DELETE FROM verification_tokens WHERE selector = $1 AND tenant_id = $2`, selector, tenantID)
		return uuid.Nil, nil, identity.ErrVerificationTokenExpired
	}

	// Guarded single-use delete: only the consumer that actually removes the row wins.
	tag, err := s.db.Exec(ctx, `DELETE FROM verification_tokens WHERE selector = $1 AND tenant_id = $2`, selector, tenantID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
	}

	return userID, metadata, nil
}

// DeleteExpiredVerificationTokens purges verification tokens past their expiry within the given
// tenant, returning the number deleted.
func (s *Store) DeleteExpiredVerificationTokens(ctx context.Context, tenantID string) (int64, error) {
	query := `DELETE FROM verification_tokens WHERE expires_at < now() AND tenant_id = $1`

	tag, err := s.db.Exec(ctx, query, tenantID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// IncrementFailedAttempts increments the failed-attempt counter for an identity,
// locking the account when the new count reaches the threshold. It is performed
// atomically in a single UPDATE statement.
func (s *Store) IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) error {
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
func (s *Store) ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error {
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

// Ping reports backend connectivity by issuing a trivial round-trip query over the store's
// handle, satisfying the optional health.Pinger seam. It returns a non-nil error when the
// backend is unreachable and honors ctx for cancellation/deadline.
func (s *Store) Ping(ctx context.Context) error {
	var ok int
	return s.db.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
