// Package passkey is the PostgreSQL passkey.Store over the v0.16 passkey_credentials table.
// Credential ids are unique per tenant. The v0.16 passkey_challenges table is left in place and
// unused.
package passkey

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/passkey"
)

// Migrations holds the schema of the store, the v0.16 files included; pgxstore registers it as
// module "passkey".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const (
	moduleName      = "passkey"
	uniqueViolation = "23505"
	columns         = `credential_id, user_id, public_key, sign_count, data, created_at, nickname, last_used_at, transports,
backup_eligible, backup_state, discoverable, suspended_at`
)

// Store is safe for concurrent use. The sign counter is compared and stored by one statement, so a
// ceremony racing another one is judged against the counter that is actually stored.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("passkey: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM passkey_credentials WHERE tenant_id = $1`, t.String()); err != nil {
		return errors.Join(errors.New("passkey: erase tenant"), err)
	}
	return nil
}

func checkCredential(c contract.Credential) error {
	switch {
	case c.Subject.IsZero():
		return errors.New("passkey: invalid credential subject")
	case len(c.ID) == 0 || len(c.ID) > contract.MaxCredentialIDLen:
		return errors.New("passkey: invalid credential id")
	case len(c.PublicKey) == 0:
		return errors.New("passkey: invalid credential public key")
	case !c.Discoverable.Valid() || c.Discoverable == contract.Legacy:
		return errors.New("passkey: invalid credential discoverable state")
	}
	return nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

func (s *Store) Save(ctx context.Context, c contract.Credential) error {
	if err := checkCredential(c); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO passkey_credentials (tenant_id, user_id, credential_id, public_key, sign_count, data, created_at,
nickname, last_used_at, transports, backup_eligible, backup_state, discoverable, suspended_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		c.Subject.Tenant.String(), c.Subject.User, []byte(c.ID), c.PublicKey, int64(c.SignCount), nonNil(c.Data),
		c.CreatedAt.UTC().Truncate(time.Microsecond), c.Nickname, utc(c.LastUsedAt), c.Transports, c.BackupEligible,
		c.BackupState, int16(c.Discoverable), utc(c.SuspendedAt))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return store.ErrConflict
	}
	if err != nil {
		return errors.Join(errors.New("passkey: save"), err)
	}
	return nil
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func scan(row pgx.Row, tenant principal.TenantID) (contract.Credential, error) {
	var c contract.Credential
	var user uuid.UUID
	var id []byte
	var signCount int64
	var discoverable int16
	err := row.Scan(&id, &user, &c.PublicKey, &signCount, &c.Data, &c.CreatedAt, &c.Nickname, &c.LastUsedAt, &c.Transports,
		&c.BackupEligible, &c.BackupState, &discoverable, &c.SuspendedAt)
	if err != nil {
		return contract.Credential{}, err
	}
	c.Subject = principal.Subject{Tenant: tenant, User: user}
	c.ID = id
	c.SignCount = uint32(signCount)
	c.Discoverable = contract.DiscoverableState(discoverable)
	c.CreatedAt = c.CreatedAt.UTC()
	c.LastUsedAt = utcOf(c.LastUsedAt)
	c.SuspendedAt = utcOf(c.SuspendedAt)
	return c, nil
}

func utcOf(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

func (s *Store) List(ctx context.Context, sub principal.Subject) ([]contract.Credential, error) {
	rows, err := s.db.Query(ctx, `SELECT `+columns+` FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at, credential_id`, sub.Tenant.String(), sub.User)
	if err != nil {
		return nil, errors.Join(errors.New("passkey: list"), err)
	}
	defer rows.Close()
	var out []contract.Credential
	for rows.Next() {
		c, err := scan(rows, sub.Tenant)
		if err != nil {
			return nil, errors.Join(errors.New("passkey: read credential"), err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("passkey: list"), err)
	}
	return out, nil
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, id contract.CredentialID) (contract.Credential, error) {
	c, err := scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM passkey_credentials WHERE tenant_id = $1 AND credential_id = $2`,
		t.String(), []byte(id)), t)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.Credential{}, store.ErrNotFound
	}
	if err != nil {
		return contract.Credential{}, errors.Join(errors.New("passkey: get"), err)
	}
	return c, nil
}

func (s *Store) Update(ctx context.Context, c contract.Credential) error {
	if !c.Discoverable.Valid() {
		return errors.New("passkey: invalid credential discoverable state")
	}
	tag, err := s.db.Exec(ctx, `UPDATE passkey_credentials
SET nickname = $4, last_used_at = $5, transports = $6, backup_eligible = $7, backup_state = $8,
    discoverable = CASE WHEN $9::smallint = 0 THEN discoverable ELSE $9::smallint END
WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3`,
		c.Subject.Tenant.String(), c.Subject.User, []byte(c.ID), c.Nickname, utc(c.LastUsedAt), c.Transports,
		c.BackupEligible, c.BackupState, int16(c.Discoverable))
	if err != nil {
		return errors.Join(errors.New("passkey: update"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateSignCount(ctx context.Context, sub principal.Subject, id contract.CredentialID, next uint32) (bool, error) {
	tenant := sub.Tenant.String()
	tag, err := s.db.Exec(ctx, `UPDATE passkey_credentials SET sign_count = $4::bigint
WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3 AND ($4::bigint > sign_count OR (sign_count = 0 AND $4::bigint = 0))`,
		tenant, sub.User, []byte(id), int64(next))
	if err != nil {
		return false, errors.Join(errors.New("passkey: update sign count"), err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3)`,
		tenant, sub.User, []byte(id)).Scan(&exists); err != nil {
		return false, errors.Join(errors.New("passkey: update sign count"), err)
	}
	if !exists {
		return false, store.ErrNotFound
	}
	return false, nil
}

func (s *Store) Suspend(ctx context.Context, sub principal.Subject, id contract.CredentialID, at time.Time) error {
	var found bool
	err := s.db.QueryRow(ctx, `WITH t AS (
    UPDATE passkey_credentials SET suspended_at = $4
    WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3 AND suspended_at IS NULL
    RETURNING 1)
SELECT EXISTS (SELECT 1 FROM t) OR EXISTS (SELECT 1 FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3)`,
		sub.Tenant.String(), sub.User, []byte(id), at.UTC().Truncate(time.Microsecond)).Scan(&found)
	if err != nil {
		return errors.Join(errors.New("passkey: suspend"), err)
	}
	if !found {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, sub principal.Subject, id contract.CredentialID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3`,
		sub.Tenant.String(), sub.User, []byte(id))
	if err != nil {
		return errors.Join(errors.New("passkey: delete"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) HasActive(ctx context.Context, sub principal.Subject) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2 AND suspended_at IS NULL)`,
		sub.Tenant.String(), sub.User).Scan(&ok)
	if err != nil {
		return false, errors.Join(errors.New("passkey: has active"), err)
	}
	return ok, nil
}

func (s *Store) AnyEnrolled(ctx context.Context) (bool, error) {
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM passkey_credentials)`).Scan(&ok); err != nil {
		return false, errors.Join(errors.New("passkey: any enrolled"), err)
	}
	return ok, nil
}

func (s *Store) CountEnrolled(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT tenant_id, user_id FROM passkey_credentials) e`).Scan(&n); err != nil {
		return 0, errors.Join(errors.New("passkey: count enrolled"), err)
	}
	return n, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM passkey_credentials WHERE tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User); err != nil {
		return errors.Join(errors.New("passkey: delete subject"), err)
	}
	return nil
}
