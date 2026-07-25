package pgx

import (
	"context"
	"embed"
	"errors"
	"strings"
	"time"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MigrationsFS embeds the SQL migration files for the identity module's Postgres schema,
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
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  tenantID,
		Email:     email,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	query := `
		INSERT INTO users (id, tenant_id, email, email_verified_at, phone, phone_verified_at, recovery_email, recovery_email_verified_at, created_at, updated_at, deleted_at, disabled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := s.db.Exec(ctx, query, user.ID, user.TenantID, user.Email, user.EmailVerifiedAt, user.Phone, user.PhoneVerifiedAt, user.RecoveryEmail, user.RecoveryEmailVerifiedAt, user.CreatedAt, user.UpdatedAt, user.DeletedAt, user.DisabledAt)
	if err != nil {
		return nil, mapError(err)
	}

	return user, nil
}

func (s *Store) FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
	query := `
		SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at, recovery_email, recovery_email_verified_at, created_at, updated_at, deleted_at, disabled_at
		FROM users
		WHERE id = $1 AND tenant_id = $2
	`
	row := s.db.QueryRow(ctx, query, id, tenantID)

	var user identity.User
	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &user.EmailVerifiedAt, &user.Phone, &user.PhoneVerifiedAt, &user.RecoveryEmail, &user.RecoveryEmailVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.DisabledAt)
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
		SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at, recovery_email, recovery_email_verified_at, created_at, updated_at, deleted_at, disabled_at
		FROM users
		WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`
	row := s.db.QueryRow(ctx, query, email, tenantID)

	var user identity.User
	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &user.EmailVerifiedAt, &user.Phone, &user.PhoneVerifiedAt, &user.RecoveryEmail, &user.RecoveryEmailVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.DisabledAt)
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

// MarkEmailVerified stamps email_verified_at on a live user, touching no other column. It is the
// narrow write behind VerifyEmail (see identity.UserStore): writing the whole row back would make
// that flow a read-modify-write and silently lose a concurrent email change.
func (s *Store) MarkEmailVerified(ctx context.Context, tenantID string, userID uuid.UUID, verifiedAt time.Time) error {
	now := time.Now().UTC()
	const query = `
		UPDATE users
		SET email_verified_at = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, verifiedAt, now, userID, tenantID)
	if err != nil {
		return err
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
// users row (deleted_at + random email), anonymizes EVERY identity row of the user, and purges any
// pending verification tokens (which would otherwise outlive the account carrying its user_id and,
// for change-email tokens, a plaintext target email — residual PII the soft delete is meant to
// erase).
//
// Anonymizing the password identity erases PII (its provider_id is the email address); anonymizing
// the external (OAuth/OIDC) ones RELEASES the provider identity so the same provider account can be
// registered again — a user who deletes their account must be able to come back through the same
// social login, which then provisions a NEW account. The anonymized key is derived per row
// ('deleted_' || identities.id) so an account holding several identities of one provider cannot
// collide on the (tenant_id, provider, provider_id) index.
//
// All three run as data-modifying CTEs gated on the user actually being live, so they commit
// together or not at all. Returns ErrUserNotFound when no live, same-tenant user matches.
func (s *Store) DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	now := time.Now().UTC()
	anonymizedEmail := "deleted_" + uuid.Must(uuid.NewV7()).String() + "@deleted.local"

	const query = `
		WITH del AS (
			UPDATE users
			SET deleted_at = $1, email = $2, updated_at = $1
			WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
			RETURNING id
		),
		ident AS (
			UPDATE identities
			SET provider_id = 'deleted_' || identities.id::text, updated_at = $1
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

	ident.ID = uuid.Must(uuid.NewV7())
	ident.TenantID = tenantID
	ident.CreatedAt = time.Now().UTC()
	ident.UpdatedAt = time.Now().UTC()

	// password_changed_at is stored as NULL when the zero value is passed (legacy / not yet set).
	var changedAt *time.Time
	if !ident.PasswordChangedAt.IsZero() {
		t := ident.PasswordChangedAt.UTC()
		changedAt = &t
	}

	// The INSERT is gated on the target being a LIVE user in the SAME tenant. The bare user_id
	// foreign key alone would accept a cross-tenant or soft-deleted user, so this EXISTS guard
	// matches the memory store's invariant exactly (mirrors CreateVerificationToken). Explicit
	// casts are required because $2/$3 appear both in the (untyped) SELECT list and the EXISTS
	// comparison.
	query := `
		INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, password_hash, password_changed_at, must_change_password, created_at, updated_at)
		SELECT $1::uuid, $2::uuid, $3::varchar, $4::varchar, $5::varchar, $6::varchar, $7::timestamptz, $8::boolean, $9::timestamptz, $10::timestamptz
		WHERE EXISTS (SELECT 1 FROM users WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL)
	`
	tag, err := s.db.Exec(ctx, query,
		ident.ID, ident.UserID, ident.TenantID, ident.Provider, ident.ProviderID,
		ident.PasswordHash, changedAt, ident.MustChangePassword,
		ident.CreatedAt, ident.UpdatedAt,
	)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		// No live, same-tenant user matched the EXISTS guard (cross-tenant, soft-deleted or
		// unknown UserID).
		return identity.ErrUserNotFound
	}

	return nil
}

func (s *Store) FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error) {
	query := `
		SELECT id, user_id, tenant_id, provider, provider_id, password_hash, failed_attempts, locked_until, password_changed_at, must_change_password, created_at, updated_at
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
		var changedAt *time.Time
		if err := rows.Scan(
			&ident.ID, &ident.UserID, &ident.TenantID, &ident.Provider, &ident.ProviderID,
			&ident.PasswordHash, &ident.FailedAttempts, &ident.LockedUntil,
			&changedAt, &ident.MustChangePassword,
			&ident.CreatedAt, &ident.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if changedAt != nil {
			ident.PasswordChangedAt = *changedAt
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
		SELECT id, user_id, tenant_id, provider, provider_id, password_hash, failed_attempts, locked_until, password_changed_at, must_change_password, created_at, updated_at
		FROM identities
		WHERE provider = $1 AND provider_id = $2 AND tenant_id = $3
	`
	row := s.db.QueryRow(ctx, query, provider, providerID, tenantID)

	var ident identity.Identity
	var changedAt *time.Time
	err := row.Scan(
		&ident.ID, &ident.UserID, &ident.TenantID, &ident.Provider, &ident.ProviderID,
		&ident.PasswordHash, &ident.FailedAttempts, &ident.LockedUntil,
		&changedAt, &ident.MustChangePassword,
		&ident.CreatedAt, &ident.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrIdentityNotFound
		}
		return nil, err
	}
	if changedAt != nil {
		ident.PasswordChangedAt = *changedAt
	}

	return &ident, nil
}

// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
// atomically clears any lockout (failed_attempts and locked_until). It also stamps
// password_changed_at=changedAt and sets must_change_password=mustChange in the same write,
// so the rotation policy can flag or clear the credential without a second round-trip.
//
// The write is gated on the owner being a LIVE, same-tenant user: a soft-deleted account reports
// ErrUserNotFound and keeps its (already anonymized) credential untouched, so a rotation can never
// re-arm a usable hash on a deleted account. The two counts come back from the same statement, which
// is what lets an unknown/deleted user be reported apart from a live user with no password identity
// (ErrIdentityNotFound).
func (s *Store) UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string, changedAt time.Time, mustChange bool) error {
	const query = `
		WITH live AS (
			SELECT id FROM users
			WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
		),
		upd AS (
			UPDATE identities
			SET password_hash = $1, failed_attempts = 0, locked_until = NULL,
			    password_changed_at = $4, must_change_password = $5, updated_at = now()
			WHERE user_id = (SELECT id FROM live) AND tenant_id = $3 AND provider = 'password'
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM live), (SELECT count(*) FROM upd)
	`
	var liveCount, updated int64
	if err := s.db.QueryRow(ctx, query, passwordHash, userID, tenantID, changedAt.UTC(), mustChange).Scan(&liveCount, &updated); err != nil {
		return err
	}
	if liveCount == 0 {
		return identity.ErrUserNotFound
	}
	if updated == 0 {
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

// DeleteVerificationTokensForUser purges the given user's pending verification tokens within the
// tenant in a single DELETE, restricted to kinds when any are supplied. An empty kinds list purges
// every kind. Both forms are covered by idx_verification_tokens_user (tenant_id, user_id, kind). It
// is idempotent: deleting nothing is a success.
func (s *Store) DeleteVerificationTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID, kinds ...string) error {
	const allKinds = `DELETE FROM verification_tokens WHERE user_id = $1 AND tenant_id = $2`
	const selectedKinds = `DELETE FROM verification_tokens WHERE user_id = $1 AND tenant_id = $2 AND kind = ANY($3::varchar[])`

	query, args := allKinds, []any{userID, tenantID}
	if len(kinds) > 0 {
		query, args = selectedKinds, []any{userID, tenantID, kinds}
	}
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return err
	}
	return nil
}

// IncrementFailedAttempts increments the failed-attempt counter for an identity,
// locking the account when the new count reaches the threshold. It is performed
// atomically in a single UPDATE statement.
//
// justLocked is derived inside the same atomic statement via RETURNING: it is true only
// when this increment crossed the threshold (the post-increment counter reaches it while
// the pre-increment counter was below it). Under concurrent failed logins the database
// serializes the UPDATEs, so exactly one caller sees justLocked == true — see the
// LockoutStore interface contract.
//
// When the row's prior lock has already expired at entry (locked_until is set but not after
// now()), the counter is restarted from zero (this attempt makes it 1) and the stale lock
// cleared in the same statement, so a new lockout cycle begins and re-crossing the threshold
// reports justLocked again.
func (s *Store) IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (justLocked bool, err error) {
	query := `
		UPDATE identities
		SET failed_attempts = CASE
				WHEN locked_until IS NOT NULL AND locked_until <= now() THEN 1
				ELSE failed_attempts + 1
			END,
			locked_until = CASE
				WHEN $3 > 0 AND (CASE
						WHEN locked_until IS NOT NULL AND locked_until <= now() THEN 1
						ELSE failed_attempts + 1
					END) >= $3 THEN now() + ($4::bigint * interval '1 millisecond')
				WHEN locked_until IS NOT NULL AND locked_until <= now() THEN NULL
				ELSE locked_until
			END,
			updated_at = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING $3 > 0 AND failed_attempts >= $3 AND failed_attempts - 1 < $3
	`
	// failed_attempts in RETURNING is the post-update value: after an expired lock it is 1
	// (the restarted count), otherwise pre-increment + 1. The predicate therefore reduces to
	// "effective pre-increment < threshold <= post-increment": the crossing transition only.
	row := s.db.QueryRow(ctx, query, identityID, tenantID, lockThreshold, lockDuration.Milliseconds())
	if err := row.Scan(&justLocked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, identity.ErrIdentityNotFound
		}
		return false, err
	}
	return justLocked, nil
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

func (s *Store) FindUserByPhone(ctx context.Context, tenantID string, phone string) (*identity.User, error) {
	query := `
		SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at, recovery_email, recovery_email_verified_at, created_at, updated_at, deleted_at, disabled_at
		FROM users
		WHERE phone = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`
	row := s.db.QueryRow(ctx, query, phone, tenantID)

	var user identity.User
	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &user.EmailVerifiedAt, &user.Phone, &user.PhoneVerifiedAt, &user.RecoveryEmail, &user.RecoveryEmailVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.DisabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUserPhone sets a live user's phone and marks it verified in one statement. The partial
// unique index (tenant_id, phone) enforces per-tenant uniqueness among live accounts, so a number
// claimed in the interim aborts the update with ErrPhoneAlreadyExists.
func (s *Store) UpdateUserPhone(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error {
	now := time.Now().UTC()
	const query = `
		UPDATE users
		SET phone = $1, phone_verified_at = $2, updated_at = $3
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, newPhone, verifiedAt, now, userID, tenantID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return identity.ErrPhoneAlreadyExists
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// UpdateUserRecoveryEmail sets a live user's recovery email and marks it verified. The recovery
// email is a secondary contact channel (not a login key) and is intentionally not unique.
func (s *Store) UpdateUserRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error {
	now := time.Now().UTC()
	const query = `
		UPDATE users
		SET recovery_email = $1, recovery_email_verified_at = $2, updated_at = $3
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, recoveryEmail, verifiedAt, now, userID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// DisableUser marks a live user as administratively disabled by setting disabled_at. It is a
// reversible suspension (the row and email slot are retained, unlike DeleteUser). It is gated on
// the user being live (deleted_at IS NULL); re-disabling an already-disabled live user simply
// overwrites disabled_at and still succeeds. Returns ErrUserNotFound when no live, same-tenant
// user matches.
func (s *Store) DisableUser(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error {
	now := time.Now().UTC()
	const query = `
		UPDATE users
		SET disabled_at = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, disabledAt, now, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// EnableUser clears a user's disabled_at, re-activating the account. It is gated on the user
// being live; enabling an account that is not disabled is a no-op-success. Returns
// ErrUserNotFound when no live, same-tenant user matches.
func (s *Store) EnableUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	now := time.Now().UTC()
	const query = `
		UPDATE users
		SET disabled_at = NULL, updated_at = $1
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
	`
	tag, err := s.db.Exec(ctx, query, now, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}
