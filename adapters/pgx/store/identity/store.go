// Package identity is the PostgreSQL identity.Store. Accounts live in the v0.16 users and identities
// tables, extended in place by 009_security_epoch.sql, 010_identifier_state.sql and 011_link_authority.sql; the epoch feed
// and the lifecycle outbox live in egauth_epoch_log and egauth_lifecycle_outbox. users.identifier_state
// defaults to IdentifiersUnchecked, so every row a v0.16 replica writes, even during a rolling
// upgrade, is listed by V016Identifiers.
package identity

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/identity"
)

// Migrations holds the schema of the store; pgxstore registers it as module "identity". Files 001
// to 008 are the v0.16 files under their v0.16 names, so a v0.16 database skips them.
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const (
	moduleName       = "identity"
	passwordProvider = "password"
	feedPage         = 1000
	epochLogLock     = int64(0x6567617574686570)
	uniqueViolation  = "23505"
)

// Store is safe for concurrent use. Every timestamp comes from the database clock. Apply runs in one
// transaction; epoch-log rows are appended under a transaction-scoped advisory lock, so their
// positions are allocated in commit order and a poller never skips a change that commits late.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("identity: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("identity: begin"), err)
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, rollback(ctx, tx))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("identity: commit"), err)
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == uniqueViolation
}

func tenantOf(s string) (principal.TenantID, error) {
	if s == "" {
		return principal.TenantID{}, nil
	}
	t, err := principal.ParseTenantID(s)
	if err != nil {
		return principal.TenantID{}, errors.Join(errors.New("identity: stored tenant"), err)
	}
	return t, nil
}

func at(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nullIdent(id contract.Identifier) *string {
	if id.IsZero() {
		return nil
	}
	v := id.Value()
	return &v
}

func canonical(k contract.IdentifierKind, v *string) bool {
	if v == nil || *v == "" {
		return true
	}
	_, err := contract.NewIdentifier(k, *v)
	return err == nil
}

func ident(k contract.IdentifierKind, v *string) contract.Identifier {
	if v == nil || *v == "" {
		return contract.Identifier{}
	}
	id, err := contract.NewIdentifier(k, *v)
	if err != nil {
		return contract.Identifier{}
	}
	return id
}

const userColumns = `u.id, u.tenant_id, u.email, u.email_verified_at, u.phone, u.phone_verified_at, u.recovery_email,
    u.recovery_email_verified_at, u.disabled_at, u.deleted_at, u.security_epoch, u.created_at,
    coalesce((SELECT bool_or(i.must_change_password) FROM identities i
        WHERE i.user_id = u.id AND i.tenant_id = u.tenant_id AND i.provider = 'password'), false)`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (contract.User, error) {
	var (
		u                                                contract.User
		tenant, email                                    string
		phone, recovery                                  *string
		verified, phoneAt, recoveryAt, disabled, deleted *time.Time
		created                                          time.Time
		epoch                                            int64
	)
	err := row.Scan(&u.Subject.User, &tenant, &email, &verified, &phone, &phoneAt, &recovery, &recoveryAt,
		&disabled, &deleted, &epoch, &created, &u.MustChange)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.User{}, store.ErrNotFound
	}
	if err != nil {
		return contract.User{}, errors.Join(errors.New("identity: read user"), err)
	}
	if u.Subject.Tenant, err = tenantOf(tenant); err != nil {
		return contract.User{}, err
	}
	u.Email = ident(contract.IdentifierEmail, &email)
	u.Phone = ident(contract.IdentifierPhone, phone)
	u.RecoveryEmail = ident(contract.IdentifierRecoveryEmail, recovery)
	u.EmailVerifiedAt, u.PhoneVerifiedAt, u.RecoveryEmailVerifiedAt = at(verified), at(phoneAt), at(recoveryAt)
	u.DisabledAt, u.DeletedAt, u.CreatedAt = at(disabled), at(deleted), created.UTC()
	u.SecurityEpoch = uint64(max(epoch, 0))
	return u, nil
}

func (s *Store) GetUser(ctx context.Context, sub principal.Subject) (contract.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id = $1 AND u.tenant_id = $2`,
		sub.User, sub.Tenant.String()))
}

func (s *Store) FindUser(ctx context.Context, t principal.TenantID, id contract.Identifier) (contract.User, error) {
	column := ""
	switch id.Kind() {
	case contract.IdentifierEmail:
		column = "email"
	case contract.IdentifierPhone:
		column = "phone"
	default:
		return contract.User{}, errors.Join(contract.ErrInvalidIdentifier, errors.New("only an email or a phone finds an account"))
	}
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users u
WHERE u.tenant_id = $1 AND u.`+column+` = $2 AND u.deleted_at IS NULL`, t.String(), id.Value()))
}

func (s *Store) exists(ctx context.Context, q migrate.Querier, sub principal.Subject) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)`,
		sub.User, sub.Tenant.String()).Scan(&ok); err != nil {
		return errors.Join(errors.New("identity: read user"), err)
	}
	if !ok {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) GetPassword(ctx context.Context, sub principal.Subject) (contract.PasswordCredential, error) {
	var (
		phc            *string
		changed, until *time.Time
		failed         int
	)
	err := s.db.QueryRow(ctx, `SELECT i.password_hash, i.password_changed_at, i.failed_attempts, i.locked_until
FROM identities i JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.user_id = $1 AND i.tenant_id = $2 AND i.provider = 'password'`, sub.User, sub.Tenant.String()).
		Scan(&phc, &changed, &failed, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.PasswordCredential{}, store.ErrNotFound
	}
	if err != nil {
		return contract.PasswordCredential{}, errors.Join(errors.New("identity: read password"), err)
	}
	cred := contract.PasswordCredential{Subject: sub, ChangedAt: at(changed), FailedAttempts: failed, LockedUntil: at(until)}
	if phc != nil {
		cred.PHC = contract.NewPasswordHash(*phc)
	}
	return cred, nil
}

func checkPolicy(p contract.LockoutPolicy) error {
	if p.Threshold <= 0 || p.Window <= 0 {
		return errors.Join(contract.ErrInvalidMutation, errors.New("lockout threshold and window must be positive"))
	}
	return nil
}

func (s *Store) RecordPasswordFailure(ctx context.Context, sub principal.Subject, p contract.LockoutPolicy) (contract.Lockout, error) {
	if err := checkPolicy(p); err != nil {
		return contract.Lockout{}, err
	}
	var out contract.Lockout
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var (
			failed    int
			until     *time.Time
			last, now time.Time
		)
		err := tx.QueryRow(ctx, `SELECT i.failed_attempts, i.locked_until, i.updated_at, now()
FROM identities i JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.user_id = $1 AND i.tenant_id = $2 AND i.provider = 'password'
FOR UPDATE OF i`, sub.User, sub.Tenant.String()).Scan(&failed, &until, &last, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return errors.Join(errors.New("identity: read lockout"), err)
		}
		locked := at(until)
		switch {
		case !locked.IsZero() && !locked.After(now):
			failed, locked = 0, time.Time{}
		case locked.IsZero() && !last.Add(p.Window).After(now):
			failed = 0
		}
		failed++
		just := false
		if locked.IsZero() && failed >= p.Threshold {
			locked, just = now.Add(p.Window).UTC().Truncate(time.Microsecond), true
		}
		if _, err := tx.Exec(ctx, `UPDATE identities SET failed_attempts = $3, locked_until = $4, updated_at = now()
WHERE user_id = $1 AND tenant_id = $2 AND provider = 'password'`, sub.User, sub.Tenant.String(), failed, nullTime(locked)); err != nil {
			return errors.Join(errors.New("identity: record password failure"), err)
		}
		out = contract.Lockout{FailedAttempts: failed, LockedUntil: locked, JustLocked: just}
		return nil
	})
	if err != nil {
		return contract.Lockout{}, err
	}
	return out, nil
}

func (s *Store) ResetPasswordFailures(ctx context.Context, sub principal.Subject) error {
	tag, err := s.db.Exec(ctx, `UPDATE identities SET failed_attempts = 0, locked_until = NULL
WHERE user_id = $1 AND tenant_id = $2 AND provider = 'password'
  AND EXISTS (SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)`, sub.User, sub.Tenant.String())
	if err != nil {
		return errors.Join(errors.New("identity: reset password failures"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

const linkColumns = `i.user_id, i.tenant_id, i.provider, i.provider_id, i.authority, i.provider_email, i.provider_email_verified, i.created_at`

func scanLink(row scanner) (contract.FederatedLink, error) {
	var (
		l        contract.FederatedLink
		tenant   string
		email    *string
		verified bool
		linked   time.Time
	)
	err := row.Scan(&l.Subject.User, &tenant, &l.Identity.Provider, &l.Identity.ProviderSubject, &l.Identity.Authority, &email, &verified, &linked)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.FederatedLink{}, store.ErrNotFound
	}
	if err != nil {
		return contract.FederatedLink{}, errors.Join(errors.New("identity: read federated link"), err)
	}
	if l.Subject.Tenant, err = tenantOf(tenant); err != nil {
		return contract.FederatedLink{}, err
	}
	l.Identity.ProviderEmail = ident(contract.IdentifierEmail, email)
	l.Identity.ProviderEmailVerified = verified && !l.Identity.ProviderEmail.IsZero()
	l.LinkedAt = linked.UTC()
	return l, nil
}

func (s *Store) FindFederated(ctx context.Context, k contract.FederatedKey) (contract.FederatedLink, error) {
	if k.Provider == passwordProvider {
		return contract.FederatedLink{}, store.ErrNotFound
	}
	return scanLink(s.db.QueryRow(ctx, `SELECT `+linkColumns+`
FROM identities i JOIN users u ON u.id = i.user_id AND u.tenant_id = i.tenant_id
WHERE i.tenant_id = $1 AND i.provider = $2 AND i.provider_id = $3 AND u.deleted_at IS NULL`,
		k.Tenant.String(), k.Provider, k.ProviderSubject))
}

func (s *Store) ListFederated(ctx context.Context, sub principal.Subject) ([]contract.FederatedLink, error) {
	if err := s.exists(ctx, s.db, sub); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+linkColumns+` FROM identities i
WHERE i.user_id = $1 AND i.tenant_id = $2 AND i.provider <> 'password'
ORDER BY i.created_at, i.provider, i.provider_id`, sub.User, sub.Tenant.String())
	if err != nil {
		return nil, errors.Join(errors.New("identity: list federated links"), err)
	}
	defer rows.Close()
	var out []contract.FederatedLink
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("identity: list federated links"), err)
	}
	return out, nil
}

func (s *Store) CurrentEpoch(ctx context.Context, sub principal.Subject) (uint64, error) {
	var epoch int64
	err := s.db.QueryRow(ctx, `SELECT security_epoch FROM users WHERE id = $1 AND tenant_id = $2`,
		sub.User, sub.Tenant.String()).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, errors.Join(errors.New("identity: read epoch"), err)
	}
	return uint64(max(epoch, 0)), nil
}

func (s *Store) EpochsChangedSince(ctx context.Context, c store.Cursor) ([]contract.EpochChange, store.Cursor, error) {
	if c.Position() > uint64(1<<63-1) {
		return nil, c, nil
	}
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, user_id, epoch, reason FROM egauth_epoch_log
WHERE seq > $1 ORDER BY seq LIMIT $2`, int64(c.Position()), feedPage)
	if err != nil {
		return nil, c, errors.Join(errors.New("identity: read epoch feed"), err)
	}
	defer rows.Close()
	var out []contract.EpochChange
	last := c.Position()
	for rows.Next() {
		var (
			seq, epoch int64
			tenant     string
			reason     int16
			ch         contract.EpochChange
		)
		if err := rows.Scan(&seq, &tenant, &ch.Subject.User, &epoch, &reason); err != nil {
			return nil, c, errors.Join(errors.New("identity: read epoch feed"), err)
		}
		if ch.Subject.Tenant, err = tenantOf(tenant); err != nil {
			return nil, c, err
		}
		ch.NewEpoch, ch.Reason = uint64(max(epoch, 0)), contract.Event(reason)
		out = append(out, ch)
		last = uint64(seq)
	}
	if err := rows.Err(); err != nil {
		return nil, c, errors.Join(errors.New("identity: read epoch feed"), err)
	}
	return out, store.RestoreCursor(last), nil
}

func (s *Store) EraseUser(ctx context.Context, sub principal.Subject) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var deleted *time.Time
		err := tx.QueryRow(ctx, `SELECT deleted_at FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
			sub.User, sub.Tenant.String()).Scan(&deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return errors.Join(errors.New("identity: read user"), err)
		}
		if deleted == nil {
			return contract.ErrNotTombstoned
		}
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM egauth_lifecycle_outbox
WHERE tenant_id = $1 AND user_id = $2 AND done_at IS NULL AND subscriber <> $3)`,
			sub.Tenant.String(), sub.User, contract.ComponentIdentity.String()).Scan(&pending); err != nil {
			return errors.Join(errors.New("identity: read outbox"), err)
		}
		if pending {
			return errors.Join(store.ErrConflict, errors.New("identity: an outbox row of the subject is not done"))
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identities WHERE user_id = $1 AND tenant_id = $2`, sub.User, sub.Tenant.String()); err != nil {
			return errors.Join(errors.New("identity: erase credentials"), err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1 AND tenant_id = $2`, sub.User, sub.Tenant.String()); err != nil {
			return errors.Join(errors.New("identity: erase user"), err)
		}
		return nil
	})
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"identities", "users", "egauth_epoch_log", "egauth_lifecycle_outbox"} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, t.String()); err != nil {
				return errors.Join(errors.New("identity: erase tenant"), err)
			}
		}
		return nil
	})
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	var total int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		for _, q := range []string{
			`DELETE FROM egauth_lifecycle_outbox WHERE done_at IS NOT NULL AND done_at < now() - $1::bigint * interval '1 microsecond'`,
			`DELETE FROM egauth_epoch_log WHERE created_at < now() - $1::bigint * interval '1 microsecond'`,
		} {
			tag, err := tx.Exec(ctx, q, contract.Retention.Microseconds())
			if err != nil {
				return errors.Join(errors.New("identity: reap expired"), err)
			}
			total += tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}
