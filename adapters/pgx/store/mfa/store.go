// Package mfa is the PostgreSQL mfa.Store. TOTP seeds are stored as the opaque sealed bytes the
// caller hands in, base64-encoded in the v0.16 secret column, next to their aad_version; the store
// holds no KEK. Recovery codes keep their hashes only. The v0.16 tables carry over unchanged.
package mfa

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/mfa"
)

// Migrations holds the schema of the store, the v0.16 files included; pgxstore registers it as
// module "mfa".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const moduleName = "mfa"

// Store is safe for concurrent use. Each lockout charge is serialised on the counter's row lock, so
// concurrent guesses on one or several instances never get more than Max comparisons.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

var (
	errInvalidSubject    = errors.New("mfa: invalid subject")
	errInvalidEnrollment = errors.New("mfa: invalid enrollment")
	errInvalidLockout    = errors.New("mfa: invalid lockout")
	errInvalidCodeHashes = errors.New("mfa: invalid recovery code hashes")
	errInvalidReseal     = errors.New("mfa: invalid reseal")
)

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("mfa: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("mfa: begin"), err)
	}
	if err := fn(tx); err != nil {
		if rb := tx.Rollback(context.WithoutCancel(ctx)); rb != nil && !errors.Is(rb, pgx.ErrTxClosed) {
			err = errors.Join(err, rb)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("mfa: commit"), err)
	}
	return nil
}

const lockSubjectSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

func lockSubject(ctx context.Context, tx pgx.Tx, sub principal.Subject) error {
	if _, err := tx.Exec(ctx, lockSubjectSQL, "egauth/mfa/"+sub.Tenant.String()+"/"+sub.User.String()); err != nil {
		return errors.Join(errors.New("mfa: lock subject"), err)
	}
	return nil
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"mfa_totp", "mfa_recovery_codes", "mfa_recovery_attempts"} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, t.String()); err != nil {
				return errors.Join(errors.New("mfa: erase tenant"), err)
			}
		}
		return nil
	})
}

func checkEnrollment(e contract.Enrollment) error {
	if e.Subject.IsZero() {
		return errInvalidSubject
	}
	if e.AADVersion != contract.AADVersionCurrent {
		return contract.ErrLegacyAADVersion
	}
	if len(e.Sealed) == 0 || e.FailedAttempts < 0 {
		return errInvalidEnrollment
	}
	return nil
}

func checkHashes(hashes []string) error {
	seen := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		if _, dup := seen[h]; h == "" || dup {
			return errInvalidCodeHashes
		}
		seen[h] = struct{}{}
	}
	return nil
}

func checkLockout(l contract.Lockout) error {
	if l.Subject.IsZero() {
		return errInvalidSubject
	}
	if l.Max < 1 || l.Duration < 0 || l.Now.IsZero() {
		return errInvalidLockout
	}
	return nil
}

func optional(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

const upsertTOTPSQL = `INSERT INTO mfa_totp (tenant_id, user_id, secret, aad_version, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9, statement_timestamp()))
ON CONFLICT (tenant_id, user_id) DO UPDATE
SET secret = EXCLUDED.secret,
    aad_version = EXCLUDED.aad_version,
    confirmed_at = EXCLUDED.confirmed_at,
    last_used_step = EXCLUDED.last_used_step,
    failed_attempts = EXCLUDED.failed_attempts,
    last_attempt_at = EXCLUDED.last_attempt_at,
    created_at = EXCLUDED.created_at`

func upsertTOTP(ctx context.Context, q migrate.Querier, e contract.Enrollment) error {
	_, err := q.Exec(ctx, upsertTOTPSQL, e.Subject.Tenant.String(), e.Subject.User,
		base64.StdEncoding.EncodeToString(e.Sealed), int16(e.AADVersion), utc(e.ConfirmedAt), e.LastUsedStep,
		int32(e.FailedAttempts), optional(e.LastAttemptAt), optional(e.CreatedAt))
	if err != nil {
		return errors.Join(errors.New("mfa: save enrollment"), err)
	}
	return nil
}

func (s *Store) SaveTOTP(ctx context.Context, e contract.Enrollment) error {
	if err := checkEnrollment(e); err != nil {
		return err
	}
	return upsertTOTP(ctx, s.db, e)
}

func (s *Store) GetTOTP(ctx context.Context, sub principal.Subject) (contract.Enrollment, error) {
	e := contract.Enrollment{Subject: sub}
	var secret string
	var version int16
	var failed int32
	var confirmed, last *time.Time
	err := s.db.QueryRow(ctx, `SELECT secret, aad_version, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at
FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User).
		Scan(&secret, &version, &confirmed, &e.LastUsedStep, &failed, &last, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.Enrollment{}, store.ErrNotFound
	}
	if err != nil {
		return contract.Enrollment{}, errors.Join(errors.New("mfa: get enrollment"), err)
	}
	sealed, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return contract.Enrollment{}, errors.Join(errors.New("mfa: stored secret is not base64"), err)
	}
	e.Sealed, e.AADVersion, e.FailedAttempts = sealed, uint8(version), int(failed)
	e.ConfirmedAt = utc(confirmed)
	if last != nil {
		e.LastAttemptAt = last.UTC()
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}

func (s *Store) DeleteTOTP(ctx context.Context, sub principal.Subject) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User); err != nil {
		return errors.Join(errors.New("mfa: delete enrollment"), err)
	}
	return nil
}

func (s *Store) HasConfirmedTOTP(ctx context.Context, sub principal.Subject) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL)`,
		sub.Tenant.String(), sub.User).Scan(&ok)
	if err != nil {
		return false, errors.Join(errors.New("mfa: has confirmed totp"), err)
	}
	return ok, nil
}

func (s *Store) AnyEnrolled(ctx context.Context) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mfa_totp) OR EXISTS (SELECT 1 FROM mfa_recovery_codes WHERE used_at IS NULL)`).Scan(&ok)
	if err != nil {
		return false, errors.Join(errors.New("mfa: any enrolled"), err)
	}
	return ok, nil
}

func (s *Store) CountEnrolled(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM (
SELECT tenant_id, user_id FROM mfa_totp
UNION
SELECT tenant_id, user_id FROM mfa_recovery_codes WHERE used_at IS NULL) e`).Scan(&n)
	if err != nil {
		return 0, errors.Join(errors.New("mfa: count enrolled"), err)
	}
	return n, nil
}

func (s *Store) MarkTOTPUsed(ctx context.Context, sub principal.Subject, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE mfa_totp SET last_used_step = $3, failed_attempts = 0, last_attempt_at = NULL
WHERE tenant_id = $1 AND user_id = $2 AND last_used_step < $3`, sub.Tenant.String(), sub.User, step)
	if err != nil {
		return false, errors.Join(errors.New("mfa: mark totp used"), err)
	}
	return tag.RowsAffected() == 1, nil
}

type counter struct {
	failed int
	last   *time.Time
}

func bump(c counter, l contract.Lockout) (counter, int) {
	now := l.Now.UTC().Truncate(time.Microsecond)
	if c.failed < l.Max {
		return counter{failed: c.failed + 1, last: &now}, c.failed + 1
	}
	if l.Duration > 0 && c.last != nil && now.Sub(*c.last) > l.Duration {
		return counter{failed: 1, last: &now}, 1
	}
	return c, l.Max + 1
}

func (s *Store) IncrementTOTPAttempts(ctx context.Context, l contract.Lockout) (int, error) {
	if err := checkLockout(l); err != nil {
		return 0, err
	}
	var reported int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var failed int32
		var last *time.Time
		err := tx.QueryRow(ctx, `SELECT failed_attempts, last_attempt_at FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`,
			l.Subject.Tenant.String(), l.Subject.User).Scan(&failed, &last)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return errors.Join(errors.New("mfa: read totp counter"), err)
		}
		next, n := bump(counter{failed: int(failed), last: utc(last)}, l)
		reported = n
		if _, err := tx.Exec(ctx, `UPDATE mfa_totp SET failed_attempts = $3, last_attempt_at = $4 WHERE tenant_id = $1 AND user_id = $2`,
			l.Subject.Tenant.String(), l.Subject.User, int32(next.failed), next.last); err != nil {
			return errors.Join(errors.New("mfa: write totp counter"), err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return reported, nil
}

func (s *Store) ResetTOTPAttempts(ctx context.Context, sub principal.Subject) error {
	if _, err := s.db.Exec(ctx, `UPDATE mfa_totp SET failed_attempts = 0, last_attempt_at = NULL WHERE tenant_id = $1 AND user_id = $2`,
		sub.Tenant.String(), sub.User); err != nil {
		return errors.Join(errors.New("mfa: reset totp attempts"), err)
	}
	return nil
}

func replaceCodes(ctx context.Context, tx pgx.Tx, sub principal.Subject, hashes []string) error {
	tenant := sub.Tenant.String()
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenant, sub.User); err != nil {
		return errors.Join(errors.New("mfa: discard recovery codes"), err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, tenant, sub.User); err != nil {
		return errors.Join(errors.New("mfa: discard recovery attempts"), err)
	}
	if len(hashes) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes (tenant_id, user_id, code_hash, used_at, created_at)
SELECT $1, $2, h, NULL, statement_timestamp() FROM unnest($3::text[]) AS h`, tenant, sub.User, hashes); err != nil {
		return errors.Join(errors.New("mfa: store recovery codes"), err)
	}
	return nil
}

func (s *Store) ConfirmEnrollment(ctx context.Context, e contract.Enrollment, codeHashes []string) error {
	if err := checkEnrollment(e); err != nil {
		return err
	}
	if e.ConfirmedAt == nil {
		return errInvalidEnrollment
	}
	if err := checkHashes(codeHashes); err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, e.Subject); err != nil {
			return err
		}
		if err := upsertTOTP(ctx, tx, e); err != nil {
			return err
		}
		return replaceCodes(ctx, tx, e.Subject, codeHashes)
	})
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, sub principal.Subject, codeHashes []string) error {
	if sub.IsZero() {
		return errInvalidSubject
	}
	if err := checkHashes(codeHashes); err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return replaceCodes(ctx, tx, sub, codeHashes)
	})
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, sub principal.Subject, codeHash string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		tenant := sub.Tenant.String()
		tag, err := tx.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at = statement_timestamp()
WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL`, tenant, sub.User, codeHash)
		if err != nil {
			return errors.Join(errors.New("mfa: consume recovery code"), err)
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE mfa_totp SET failed_attempts = 0, last_attempt_at = NULL WHERE tenant_id = $1 AND user_id = $2`, tenant, sub.User); err != nil {
			return errors.Join(errors.New("mfa: reset totp counter"), err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, tenant, sub.User); err != nil {
			return errors.Join(errors.New("mfa: reset recovery counter"), err)
		}
		return nil
	})
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, sub principal.Subject) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return replaceCodes(ctx, tx, sub, nil)
	})
}

func (s *Store) IncrementRecoveryAttempts(ctx context.Context, l contract.Lockout) (int, error) {
	if err := checkLockout(l); err != nil {
		return 0, err
	}
	tenant := l.Subject.Tenant.String()
	var reported int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_attempts (tenant_id, user_id, failed_attempts, last_attempt_at)
VALUES ($1, $2, 0, NULL) ON CONFLICT (tenant_id, user_id) DO NOTHING`, tenant, l.Subject.User); err != nil {
			return errors.Join(errors.New("mfa: create recovery counter"), err)
		}
		var failed int32
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT failed_attempts, last_attempt_at FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`,
			tenant, l.Subject.User).Scan(&failed, &last); err != nil {
			return errors.Join(errors.New("mfa: read recovery counter"), err)
		}
		next, n := bump(counter{failed: int(failed), last: utc(last)}, l)
		reported = n
		if _, err := tx.Exec(ctx, `UPDATE mfa_recovery_attempts SET failed_attempts = $3, last_attempt_at = $4 WHERE tenant_id = $1 AND user_id = $2`,
			tenant, l.Subject.User, int32(next.failed), next.last); err != nil {
			return errors.Join(errors.New("mfa: write recovery counter"), err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return reported, nil
}

func (s *Store) ResetRecoveryAttempts(ctx context.Context, sub principal.Subject) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM mfa_recovery_attempts WHERE tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User); err != nil {
		return errors.Join(errors.New("mfa: reset recovery attempts"), err)
	}
	return nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		for _, table := range []string{"mfa_totp", "mfa_recovery_codes", "mfa_recovery_attempts"} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User); err != nil {
				return errors.Join(errors.New("mfa: delete subject"), err)
			}
		}
		return nil
	})
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM mfa_totp WHERE aad_version = 0`).Scan(&n); err != nil {
		return 0, errors.Join(errors.New("mfa: count legacy sealed"), err)
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]contract.V016Row, store.Cursor, error) {
	if limit < 1 {
		return nil, after, errors.New("mfa: limit must be positive")
	}
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, user_id, secret FROM mfa_totp
WHERE aad_version = 0 AND seq > $1 ORDER BY seq LIMIT $2`, int64(after.Position()), limit)
	if err != nil {
		return nil, after, errors.Join(errors.New("mfa: list legacy sealed"), err)
	}
	defer rows.Close()
	var out []contract.V016Row
	next := after
	for rows.Next() {
		var seq int64
		var tenant, secret string
		var user uuid.UUID
		if err := rows.Scan(&seq, &tenant, &user, &secret); err != nil {
			return nil, after, errors.Join(errors.New("mfa: read legacy sealed"), err)
		}
		sealed, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return nil, after, errors.Join(errors.New("mfa: legacy secret is not base64, row "+user.String()), err)
		}
		t := principal.TenantID{}
		if tenant != "" {
			if t, err = principal.ParseTenantID(tenant); err != nil {
				return nil, after, errors.Join(errors.New("mfa: legacy row "+user.String()+" has an invalid tenant id"), err)
			}
		}
		out = append(out, contract.V016Row{Ref: contract.SealedRef{Subject: principal.Subject{Tenant: t, User: user}}, Sealed: sealed})
		next = store.RestoreCursor(uint64(seq))
	}
	if err := rows.Err(); err != nil {
		return nil, after, errors.Join(errors.New("mfa: list legacy sealed"), err)
	}
	return out, next, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r contract.Reseal) (bool, error) {
	if r.Ref.Subject.IsZero() || len(r.Old) == 0 || len(r.New) == 0 {
		return false, errInvalidReseal
	}
	tag, err := s.db.Exec(ctx, `UPDATE mfa_totp SET secret = $3, aad_version = $4
WHERE tenant_id = $1 AND user_id = $2 AND secret = $5`, r.Ref.Subject.Tenant.String(), r.Ref.Subject.User,
		base64.StdEncoding.EncodeToString(r.New), int16(contract.AADVersionCurrent), base64.StdEncoding.EncodeToString(bytes.Clone(r.Old)))
	if err != nil {
		return false, errors.Join(errors.New("mfa: replace sealed"), err)
	}
	return tag.RowsAffected() == 1, nil
}
