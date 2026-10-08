// Package sessions is the PostgreSQL sessions.Store. Sessions live in egauth_sessions and their
// revocation feed in egauth_session_revocations; the v0.16 sessions table is ignored.
package sessions

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
	contract "github.com/JLugagne/egauth/store/sessions"
)

// Migrations holds the schema of the store, the v0.16 files included; pgxstore registers it as
// module "sessions".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const moduleName = "sessions"

// Store is safe for concurrent use. Every decision reads the database clock at the statement that
// takes it. Rotate refuses a Next that ends after the row's absolute expiry. Inserts and bulk
// revocations of one subject serialise on a per-subject advisory lock, and feed rows are appended
// under one feed lock taken last, so feed positions are handed out in commit order.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("sessions: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("sessions: begin"), err)
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, rollback(ctx, tx))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("sessions: commit"), err)
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

const (
	lockSubjectSQL = `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0)), pg_advisory_xact_lock(hashtextextended($2, 0))`
	lockTenantSQL  = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
	lockFeedSQL    = `SELECT pg_advisory_xact_lock(hashtextextended('egauth/sessions/revocations', 0))`
	liveSQL        = `idle_expires_at > statement_timestamp() AND absolute_expires_at > statement_timestamp()`
)

func tenantLock(t principal.TenantID) string { return "egauth/sessions/tenant/" + t.String() }

func lockSubject(ctx context.Context, tx pgx.Tx, sub principal.Subject) error {
	if _, err := tx.Exec(ctx, lockSubjectSQL, tenantLock(sub.Tenant), "egauth/sessions/subject/"+sub.Tenant.String()+"/"+sub.User.String()); err != nil {
		return errors.Join(errors.New("sessions: lock subject"), err)
	}
	return nil
}

func endRows(ctx context.Context, tx pgx.Tx, where string, args ...any) error {
	rows, err := tx.Query(ctx, `DELETE FROM egauth_sessions WHERE `+where+`
RETURNING tenant_id, id, absolute_expires_at`, args...)
	if err != nil {
		return errors.Join(errors.New("sessions: end"), err)
	}
	var (
		tenants []string
		ids     []string
		expires []time.Time
	)
	for rows.Next() {
		var (
			tenant string
			id     uuid.UUID
			exp    time.Time
		)
		if err := rows.Scan(&tenant, &id, &exp); err != nil {
			rows.Close()
			return errors.Join(errors.New("sessions: read ended session"), err)
		}
		tenants, ids, expires = append(tenants, tenant), append(ids, id.String()), append(expires, exp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return errors.Join(errors.New("sessions: end"), err)
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, lockFeedSQL); err != nil {
		return errors.Join(errors.New("sessions: lock revocation feed"), err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO egauth_session_revocations (tenant_id, session_id, created_at, expires_at)
SELECT u.tenant, u.id, statement_timestamp(), u.expires
FROM unnest($1::text[], $2::uuid[], $3::timestamptz[]) AS u(tenant, id, expires)
ORDER BY u.tenant, u.id`, tenants, ids, expires); err != nil {
		return errors.Join(errors.New("sessions: append revocation feed"), err)
	}
	return nil
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockTenantSQL, tenantLock(t)); err != nil {
			return errors.Join(errors.New("sessions: lock tenant"), err)
		}
		return endRows(ctx, tx, `tenant_id = $1`, t.String())
	})
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM egauth_sessions WHERE idle_expires_at <= statement_timestamp() OR absolute_expires_at <= statement_timestamp()`,
		`DELETE FROM egauth_session_revocations WHERE expires_at <= statement_timestamp()`,
	} {
		tag, err := s.db.Exec(ctx, q)
		if err != nil {
			return total, errors.Join(errors.New("sessions: reap expired"), err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

const columns = `id, token_hash, tenant_id, user_id, lineage, attrs, app_claims, epoch, client_fingerprint,
    idle_expires_at, absolute_expires_at, checked_at, created_at`

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func scan(row pgx.Row) (contract.Record, error) {
	var (
		r      contract.Row
		tenant string
		sealed []byte
	)
	if err := row.Scan(&r.ID, &r.TokenHash, &tenant, &r.Subject.User, &r.Lineage, &sealed, &r.AppClaims, &r.SecurityEpoch,
		&r.ClientFingerprint, &r.IdleExpiresAt, &r.AbsoluteExpiresAt, &r.CheckedAt, &r.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return contract.Record{}, store.ErrNotFound
		}
		return contract.Record{}, errors.Join(errors.New("sessions: read session"), err)
	}
	t, err := principal.ParseTenantID(tenant)
	if err != nil {
		return contract.Record{}, errors.Join(contract.ErrInvalidRecord, err)
	}
	r.Subject.Tenant = t
	r.Sealed = principal.SealedFromBytes(sealed)
	r.AppClaims = nonEmpty(r.AppClaims)
	r.ClientFingerprint = nonEmpty(r.ClientFingerprint)
	r.IdleExpiresAt = r.IdleExpiresAt.UTC()
	r.AbsoluteExpiresAt = r.AbsoluteExpiresAt.UTC()
	r.CheckedAt = r.CheckedAt.UTC()
	r.CreatedAt = r.CreatedAt.UTC()
	return contract.Restore(r)
}

func claimsOf(r contract.Record) []byte {
	if c := r.AppClaims(); c != nil {
		return c
	}
	return []byte{}
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func insert(ctx context.Context, tx pgx.Tx, r contract.Record) error {
	tag, err := tx.Exec(ctx, `INSERT INTO egauth_sessions (`+columns+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT DO NOTHING`,
		r.ID(), r.TokenHash(), r.Tenant().String(), r.Subject().User, r.Lineage(), r.Sealed().Bytes(), claimsOf(r), r.Epoch(),
		nonEmpty(r.ClientFingerprint()), r.IdleExpiresAt(), r.AbsoluteExpiresAt(), r.CheckedAt(), r.CreatedAt())
	if err != nil {
		return errors.Join(errors.New("sessions: insert"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *Store) Create(ctx context.Context, r contract.Record) error {
	if r.IsZero() {
		return contract.ErrInvalidRecord
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, r.Subject()); err != nil {
			return err
		}
		return insert(ctx, tx, r)
	})
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (contract.Record, error) {
	return scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM egauth_sessions
WHERE token_hash = $1 AND tenant_id = $2 AND `+liveSQL, tokenHash, t.String()))
}

func (s *Store) Touch(ctx context.Context, t principal.TenantID, tokenHash []byte, idleUntil time.Time) (time.Time, error) {
	var idle time.Time
	err := s.db.QueryRow(ctx, `UPDATE egauth_sessions
SET idle_expires_at = GREATEST(idle_expires_at, LEAST($3::timestamptz, absolute_expires_at))
WHERE token_hash = $1 AND tenant_id = $2 AND `+liveSQL+`
RETURNING idle_expires_at`, tokenHash, t.String(), idleUntil).Scan(&idle)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, store.ErrNotFound
	}
	if err != nil {
		return time.Time{}, errors.Join(errors.New("sessions: touch"), err)
	}
	return idle.UTC(), nil
}

func (s *Store) Rotate(ctx context.Context, req contract.RotateRequest) error {
	if req.Next.IsZero() {
		return contract.ErrInvalidRecord
	}
	n := req.Next
	tag, err := s.db.Exec(ctx, `UPDATE egauth_sessions
SET token_hash = $5, attrs = $6, app_claims = $7, epoch = $8, client_fingerprint = $9,
    idle_expires_at = $10, absolute_expires_at = $11, checked_at = $12
WHERE token_hash = $1 AND tenant_id = $2 AND id = $3 AND user_id = $4 AND lineage = $13
    AND absolute_expires_at >= $11 AND `+liveSQL,
		req.Previous, n.Tenant().String(), n.ID(), n.Subject().User, n.TokenHash(), n.Sealed().Bytes(), claimsOf(n), n.Epoch(),
		nonEmpty(n.ClientFingerprint()), n.IdleExpiresAt(), n.AbsoluteExpiresAt(), n.CheckedAt(), n.Lineage())
	if uniqueViolation(err) {
		return store.ErrConflict
	}
	if err != nil {
		return errors.Join(errors.New("sessions: rotate"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *Store) Replace(ctx context.Context, req contract.ReplaceRequest) error {
	if req.Next.IsZero() {
		return errors.Join(contract.ErrInvalidRecord, errors.New("a next record is required"))
	}
	n := req.Next
	if n.ID() == req.Previous {
		return store.ErrConflict
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, n.Subject()); err != nil {
			return err
		}
		var id uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM egauth_sessions
WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND lineage = $4 AND `+liveSQL+`
FOR UPDATE`, req.Previous, n.Tenant().String(), n.Subject().User, n.Lineage()).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrConflict
		}
		if err != nil {
			return errors.Join(errors.New("sessions: read replaced session"), err)
		}
		if err := insert(ctx, tx, n); err != nil {
			return err
		}
		return endRows(ctx, tx, `id = $1`, req.Previous)
	})
}

func (s *Store) Revoke(ctx context.Context, t principal.TenantID, tokenHash []byte) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		return endRows(ctx, tx, `token_hash = $1 AND tenant_id = $2`, tokenHash, t.String())
	})
}

func (s *Store) RevokeSession(ctx context.Context, sub principal.Subject, id uuid.UUID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return endRows(ctx, tx, `id = $1 AND tenant_id = $2 AND user_id = $3`, id, sub.Tenant.String(), sub.User)
	})
}

func (s *Store) RevokeForSubject(ctx context.Context, sub principal.Subject, exceptLineage uuid.UUID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return endRows(ctx, tx, `tenant_id = $1 AND user_id = $2 AND ($3::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR lineage <> $3::uuid)`,
			sub.Tenant.String(), sub.User, exceptLineage.String())
	})
}

func (s *Store) RevocationsSince(ctx context.Context, c store.Cursor) ([]contract.Revocation, store.Cursor, error) {
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, session_id, created_at FROM egauth_session_revocations
WHERE seq > $1 ORDER BY seq`, int64(c.Position()))
	if err != nil {
		return nil, c, errors.Join(errors.New("sessions: read revocation feed"), err)
	}
	defer rows.Close()
	out := []contract.Revocation{}
	last := c
	for rows.Next() {
		var (
			seq    int64
			tenant string
			r      contract.Revocation
		)
		if err := rows.Scan(&seq, &tenant, &r.Session, &r.At); err != nil {
			return nil, c, errors.Join(errors.New("sessions: read revocation"), err)
		}
		if r.Tenant, err = principal.ParseTenantID(tenant); err != nil {
			return nil, c, errors.Join(errors.New("sessions: read revocation tenant"), err)
		}
		r.At = r.At.UTC()
		out = append(out, r)
		last = store.RestoreCursor(uint64(seq))
	}
	if err := rows.Err(); err != nil {
		return nil, c, errors.Join(errors.New("sessions: read revocation feed"), err)
	}
	return out, last, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return endRows(ctx, tx, `tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User)
	})
}
