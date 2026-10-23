// Package tokens is the PostgreSQL tokens.Store. Refresh families live in egauth_refresh_tokens and
// their revocation feed in egauth_revocations; API keys stay in the v0.16 tokens table, whose legacy
// refresh rows are ignored until they expire and are reaped.
//
// A v0.16 API key (app_claims NULL) carries over: a service or system key, whose v0.16 subject was its
// own id, is owned by its recorded creator, and its AppClaims are the v0.16 Roles, Scopes and Groups
// as the JSON object {"roles":[...],"scopes":[...],"groups":[...]}; AMR, audiences and custom claims
// are dropped. Its CreatedEpoch is 0. A v0.16 key with no recorded creator keeps its own id as owner,
// which names no account, so it verifies as having no owner.
package tokens

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/tokens"
)

// Migrations holds the schema of the store, the v0.16 files included; pgxstore registers it as
// module "tokens".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const moduleName = "tokens"

// Store is safe for concurrent use. Every decision reads the database clock at the statement that
// takes it, after any lock wait, never an instant carried by a request (T-21). A rotation whose Next
// ends after the presented token's family is refused with store.ErrConflict. Writes to one
// subject's families serialise on a per-subject advisory lock, and feed rows are appended under one feed lock taken last, so feed positions are handed out
// in commit order.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("tokens: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("tokens: begin"), err)
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, rollback(ctx, tx))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("tokens: commit"), err)
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
	lockFeedSQL    = `SELECT pg_advisory_xact_lock(hashtextextended('egauth/tokens/revocations', 0))`
	lockKeyIDSQL   = `SELECT pg_advisory_xact_lock(hashtextextended('egauth/tokens/api-key/' || $1::text, 0))`
	ownerSQL       = `(CASE WHEN created_by IS NOT NULL AND id = user_id THEN created_by ELSE user_id END)`
)

func ownedBy(param string) string {
	return `(user_id = ` + param + ` OR created_by = ` + param + `) AND ` + ownerSQL + ` = ` + param
}

func legacyList(name string) string {
	upper := strings.ToUpper(name[:1]) + name[1:]
	return `coalesce(CASE WHEN jsonb_typeof(claims->'` + upper + `') = 'array' THEN claims->'` + upper + `' END,
        CASE WHEN jsonb_typeof(claims->'` + name + `') = 'array' THEN claims->'` + name + `' END, '[]'::jsonb)`
}

func tenantLock(t principal.TenantID) string { return "egauth/tokens/tenant/" + t.String() }

func lockSubject(ctx context.Context, tx pgx.Tx, sub principal.Subject) error {
	if _, err := tx.Exec(ctx, lockSubjectSQL, tenantLock(sub.Tenant), "egauth/tokens/subject/"+sub.Tenant.String()+"/"+sub.User.String()); err != nil {
		return errors.Join(errors.New("tokens: lock subject"), err)
	}
	return nil
}

type revoked struct {
	tenant  string
	family  uuid.UUID
	expires time.Time
}

func revokeRows(ctx context.Context, tx pgx.Tx, where string, args ...any) error {
	rows, err := tx.Query(ctx, `UPDATE egauth_refresh_tokens SET revoked_at = statement_timestamp()
WHERE revoked_at IS NULL AND `+where+`
RETURNING tenant_id, family_id, family_expires_at`, args...)
	if err != nil {
		return errors.Join(errors.New("tokens: revoke"), err)
	}
	var out []revoked
	for rows.Next() {
		var r revoked
		if err := rows.Scan(&r.tenant, &r.family, &r.expires); err != nil {
			rows.Close()
			return errors.Join(errors.New("tokens: read revoked family"), err)
		}
		i := slices.IndexFunc(out, func(o revoked) bool { return o.tenant == r.tenant && o.family == r.family })
		if i < 0 {
			out = append(out, r)
			continue
		}
		if r.expires.After(out[i].expires) {
			out[i].expires = r.expires
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return errors.Join(errors.New("tokens: revoke"), err)
	}
	return appendFeed(ctx, tx, out)
}

func appendFeed(ctx context.Context, tx pgx.Tx, revs []revoked) error {
	if len(revs) == 0 {
		return nil
	}
	slices.SortFunc(revs, func(a, b revoked) int {
		if c := strings.Compare(a.tenant, b.tenant); c != 0 {
			return c
		}
		return bytes.Compare(a.family[:], b.family[:])
	})
	tenants := make([]string, 0, len(revs))
	families := make([]string, 0, len(revs))
	expires := make([]time.Time, 0, len(revs))
	for _, r := range revs {
		tenants = append(tenants, r.tenant)
		families = append(families, r.family.String())
		expires = append(expires, r.expires)
	}
	if _, err := tx.Exec(ctx, lockFeedSQL); err != nil {
		return errors.Join(errors.New("tokens: lock revocation feed"), err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO egauth_revocations (tenant_id, family_id, created_at, expires_at)
SELECT u.tenant, u.family, statement_timestamp(), u.expires
FROM unnest($1::text[], $2::uuid[], $3::timestamptz[]) WITH ORDINALITY AS u(tenant, family, expires, ord)
ORDER BY u.ord`, tenants, families, expires); err != nil {
		return errors.Join(errors.New("tokens: append revocation feed"), err)
	}
	return nil
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockTenantSQL, tenantLock(t)); err != nil {
			return errors.Join(errors.New("tokens: lock tenant"), err)
		}
		if err := revokeRows(ctx, tx, `tenant_id = $1`, t.String()); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM egauth_refresh_tokens WHERE tenant_id = $1`,
			`DELETE FROM tokens WHERE tenant_id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, t.String()); err != nil {
				return errors.Join(errors.New("tokens: erase tenant"), err)
			}
		}
		return nil
	})
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM egauth_refresh_tokens WHERE idle_expires_at <= statement_timestamp() OR family_expires_at <= statement_timestamp()`,
		`DELETE FROM egauth_revocations WHERE expires_at <= statement_timestamp()`,
		`DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at <= statement_timestamp()`,
	} {
		tag, err := s.db.Exec(ctx, q)
		if err != nil {
			return total, errors.Join(errors.New("tokens: reap expired"), err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

const refreshColumns = `hash, tenant_id, family_id, lineage, user_id, attrs, app_claims, epoch, client_fingerprint,
    idle_expires_at, family_expires_at, created_at`

type scanner interface{ Scan(dest ...any) error }

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func scanRefresh(row scanner, extra ...any) (contract.RefreshRow, error) {
	var (
		r      contract.RefreshRow
		tenant string
		sealed []byte
	)
	dest := append([]any{
		&r.TokenHash, &tenant, &r.Family, &r.Lineage, &r.Subject.User, &sealed, &r.AppClaims, &r.SecurityEpoch,
		&r.ClientFingerprint, &r.IdleExpiresAt, &r.FamilyExpiresAt, &r.CreatedAt,
	}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, store.ErrNotFound
		}
		return r, errors.Join(errors.New("tokens: read refresh token"), err)
	}
	t, err := tenantOf(tenant)
	if err != nil {
		return r, errors.Join(contract.ErrInvalidRecord, err)
	}
	r.Subject.Tenant = t
	r.Sealed = principal.SealedFromBytes(sealed)
	r.AppClaims = nonEmpty(r.AppClaims)
	r.ClientFingerprint = nonEmpty(r.ClientFingerprint)
	r.IdleExpiresAt = r.IdleExpiresAt.UTC()
	r.FamilyExpiresAt = r.FamilyExpiresAt.UTC()
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func insertRefresh(ctx context.Context, tx pgx.Tx, r contract.RefreshRecord) error {
	claims := r.AppClaims()
	if claims == nil {
		claims = []byte{}
	}
	tag, err := tx.Exec(ctx, `INSERT INTO egauth_refresh_tokens (`+refreshColumns+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (hash) DO NOTHING`,
		r.TokenHash(), r.Tenant().String(), r.Family(), r.Lineage(), r.Subject().User, r.Sealed().Bytes(), claims,
		r.Epoch(), nonEmpty(r.ClientFingerprint()), r.IdleExpiresAt(), r.FamilyExpiresAt(), r.CreatedAt())
	if err != nil {
		return errors.Join(errors.New("tokens: insert refresh token"), err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrConflict
	}
	return nil
}

func familyExists(ctx context.Context, tx pgx.Tx, t principal.TenantID, family uuid.UUID) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM egauth_refresh_tokens WHERE tenant_id = $1 AND family_id = $2)`,
		t.String(), family).Scan(&exists); err != nil {
		return false, errors.Join(errors.New("tokens: look up family"), err)
	}
	return exists, nil
}

func (s *Store) Create(ctx context.Context, r contract.RefreshRecord) error {
	if r.IsZero() {
		return contract.ErrInvalidRecord
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, r.Subject()); err != nil {
			return err
		}
		exists, err := familyExists(ctx, tx, r.Tenant(), r.Family())
		if err != nil {
			return err
		}
		if exists {
			return store.ErrConflict
		}
		return insertRefresh(ctx, tx, r)
	})
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (contract.RefreshRecord, error) {
	var ended, idle, consumed bool
	row, err := scanRefresh(s.db.QueryRow(ctx, `SELECT `+refreshColumns+`,
    revoked_at IS NOT NULL OR family_expires_at <= statement_timestamp(), idle_expires_at <= statement_timestamp(),
    consumed_at IS NOT NULL
FROM egauth_refresh_tokens WHERE hash = $1 AND tenant_id = $2`, tokenHash, t.String()), &ended, &idle, &consumed)
	switch {
	case err != nil:
		return contract.RefreshRecord{}, err
	case ended:
		return contract.RefreshRecord{}, contract.ErrRevoked
	case idle && !consumed:
		return contract.RefreshRecord{}, store.ErrNotFound
	}
	return contract.RestoreRefreshRecord(row)
}

type presented struct {
	user        uuid.UUID
	lineage     uuid.UUID
	family      uuid.UUID
	ends        time.Time
	ended       bool
	idle        bool
	consumed    bool
	withinGrace bool
	consumedBy  []byte
}

func (s *Store) ConsumeForRotation(ctx context.Context, req contract.RotationRequest) (contract.Rotation, error) {
	if req.Next.IsZero() || len(req.Presented) != contract.HashLen {
		return contract.Rotation{}, errors.Join(contract.ErrInvalidRecord, errors.New("a presented digest and a next record are required"))
	}
	next := req.Next
	var (
		rot     contract.Rotation
		outcome error
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, next.Subject()); err != nil {
			return err
		}
		var p presented
		err := tx.QueryRow(ctx, `SELECT user_id, lineage, family_id, family_expires_at,
    revoked_at IS NOT NULL OR family_expires_at <= statement_timestamp(), idle_expires_at <= statement_timestamp(), consumed_at IS NOT NULL,
    coalesce(statement_timestamp() - consumed_at < $3::bigint * interval '1 microsecond', false), consumed_by
FROM egauth_refresh_tokens WHERE hash = $1 AND tenant_id = $2
FOR UPDATE`, req.Presented, next.Tenant().String(), contract.ReuseGrace.Microseconds()).Scan(
			&p.user, &p.lineage, &p.family, &p.ends, &p.ended, &p.idle, &p.consumed, &p.withinGrace, &p.consumedBy)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = store.ErrNotFound
			return nil
		case err != nil:
			return errors.Join(errors.New("tokens: read presented token"), err)
		case p.ended:
			outcome = contract.ErrRevoked
			return nil
		case p.idle && !p.consumed:
			outcome = store.ErrNotFound
			return nil
		case p.user != next.Subject().User || p.lineage != next.Lineage() || p.family != next.Family():
			outcome = store.ErrConflict
			return nil
		case p.consumed && p.withinGrace && len(p.consumedBy) > 0 && bytes.Equal(p.consumedBy, next.ClientFingerprint()):
			outcome = contract.ErrConcurrent
			return nil
		case p.consumed:
			outcome = contract.ErrReused
			return revokeRows(ctx, tx, `tenant_id = $1 AND family_id = $2`, next.Tenant().String(), p.family)
		case next.FamilyExpiresAt().Truncate(time.Microsecond).After(p.ends):
			outcome = store.ErrConflict
			return nil
		}
		var consumedAt time.Time
		if err := tx.QueryRow(ctx, `UPDATE egauth_refresh_tokens SET consumed_at = statement_timestamp(), consumed_by = $2
WHERE hash = $1 RETURNING consumed_at`, req.Presented, nonEmpty(next.ClientFingerprint())).Scan(&consumedAt); err != nil {
			return errors.Join(errors.New("tokens: consume presented token"), err)
		}
		if err := insertRefresh(ctx, tx, next); err != nil {
			return err
		}
		rot = contract.Rotation{Family: p.family, ConsumedAt: consumedAt.UTC()}
		return nil
	})
	if err != nil {
		return contract.Rotation{}, err
	}
	if outcome != nil {
		return contract.Rotation{}, outcome
	}
	return rot, nil
}

func (s *Store) Reissue(ctx context.Context, req contract.ReissueRequest) error {
	if req.Next.IsZero() {
		return contract.ErrInvalidRecord
	}
	next := req.Next
	if next.Family() == req.Family {
		return store.ErrConflict
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, next.Subject()); err != nil {
			return err
		}
		var count int
		var foreign, revokedAny, live bool
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(bool_or(user_id <> $3 OR lineage <> $4), false),
    coalesce(bool_or(revoked_at IS NOT NULL), false), coalesce(max(family_expires_at) > statement_timestamp(), false)
FROM egauth_refresh_tokens WHERE tenant_id = $1 AND family_id = $2`,
			next.Tenant().String(), req.Family, next.Subject().User, next.Lineage()).Scan(&count, &foreign, &revokedAny, &live); err != nil {
			return errors.Join(errors.New("tokens: read reissued family"), err)
		}
		if count == 0 || foreign || revokedAny || !live {
			return store.ErrConflict
		}
		taken, err := familyExists(ctx, tx, next.Tenant(), next.Family())
		if err != nil {
			return err
		}
		if taken {
			return store.ErrConflict
		}
		if err := insertRefresh(ctx, tx, next); err != nil {
			return err
		}
		return revokeRows(ctx, tx, `tenant_id = $1 AND family_id = $2`, next.Tenant().String(), req.Family)
	})
}

func (s *Store) FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (contract.FamilyState, error) {
	st := contract.FamilyState{Subject: principal.Subject{Tenant: t}}
	err := s.db.QueryRow(ctx, `SELECT (array_agg(user_id))[1], (array_agg(lineage))[1], bool_or(revoked_at IS NOT NULL),
    max(family_expires_at)
FROM egauth_refresh_tokens WHERE tenant_id = $1 AND family_id = $2
HAVING count(*) > 0`, t.String(), family).Scan(&st.Subject.User, &st.Lineage, &st.Revoked, &st.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.FamilyState{}, store.ErrNotFound
	}
	if err != nil {
		return contract.FamilyState{}, errors.Join(errors.New("tokens: read family state"), err)
	}
	st.ExpiresAt = st.ExpiresAt.UTC()
	return st, nil
}

func (s *Store) RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var user uuid.UUID
		err := tx.QueryRow(ctx, `SELECT user_id FROM egauth_refresh_tokens WHERE tenant_id = $1 AND family_id = $2 LIMIT 1`,
			t.String(), family).Scan(&user)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return errors.Join(errors.New("tokens: read family owner"), err)
		}
		if err := lockSubject(ctx, tx, principal.Subject{Tenant: t, User: user}); err != nil {
			return err
		}
		return revokeRows(ctx, tx, `tenant_id = $1 AND family_id = $2`, t.String(), family)
	})
}

func (s *Store) RevokeForSubject(ctx context.Context, sub principal.Subject, exceptLineage uuid.UUID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		return revokeRows(ctx, tx, `tenant_id = $1 AND user_id = $2 AND ($3::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR lineage <> $3::uuid)`,
			sub.Tenant.String(), sub.User, exceptLineage.String())
	})
}

func (s *Store) RevocationsSince(ctx context.Context, c store.Cursor) ([]contract.Revocation, store.Cursor, error) {
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, family_id, created_at FROM egauth_revocations
WHERE seq > $1 ORDER BY seq`, int64(c.Position()))
	if err != nil {
		return nil, c, errors.Join(errors.New("tokens: read revocation feed"), err)
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
		if err := rows.Scan(&seq, &tenant, &r.Family, &r.At); err != nil {
			return nil, c, errors.Join(errors.New("tokens: read revocation"), err)
		}
		if r.Tenant, err = tenantOf(tenant); err != nil {
			return nil, c, errors.Join(errors.New("tokens: read revocation tenant"), err)
		}
		r.At = r.At.UTC()
		out = append(out, r)
		last = store.RestoreCursor(uint64(seq))
	}
	if err := rows.Err(); err != nil {
		return nil, c, errors.Join(errors.New("tokens: read revocation feed"), err)
	}
	return out, last, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockSubject(ctx, tx, sub); err != nil {
			return err
		}
		if err := revokeRows(ctx, tx, `tenant_id = $1 AND user_id = $2`, sub.Tenant.String(), sub.User); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM egauth_refresh_tokens WHERE tenant_id = $1 AND user_id = $2`,
			`DELETE FROM tokens WHERE tenant_id = $1 AND (user_id = $2 OR created_by = $2)`,
		} {
			if _, err := tx.Exec(ctx, q, sub.Tenant.String(), sub.User); err != nil {
				return errors.Join(errors.New("tokens: delete for subject"), err)
			}
		}
		return nil
	})
}

func (s *Store) CreateAPIKey(ctx context.Context, k contract.APIKey) error {
	if err := k.Validate(); err != nil {
		return err
	}
	claims := k.AppClaims
	if claims == nil {
		claims = []byte{}
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockKeyIDSQL, k.ID.String()); err != nil {
			return errors.Join(errors.New("tokens: lock api key id"), err)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO tokens
    (id, tenant_id, token_hash, user_id, claims, type, name, created_by, app_claims, created_epoch, created_at, expires_at, revoked_at)
SELECT $1, $2, $3, $4, '{}'::jsonb, $5, $6, $4, $7, $8, $9, $10, $11
WHERE NOT EXISTS (SELECT 1 FROM tokens WHERE id = $1 AND claims IS NOT NULL)
ON CONFLICT (tenant_id, token_hash) DO NOTHING`,
			k.ID, k.Owner.Tenant.String(), hex.EncodeToString(k.KeyHash), k.Owner.User, k.Kind, k.Name, claims,
			k.CreatedEpoch, k.CreatedAt, optionalTime(k.ExpiresAt), optionalTime(k.RevokedAt))
		if err != nil {
			return errors.Join(errors.New("tokens: insert api key"), err)
		}
		if tag.RowsAffected() == 0 {
			return store.ErrConflict
		}
		return nil
	})
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

var apiKeyColumns = `id, tenant_id, ` + ownerSQL + `, token_hash, type, coalesce(name, prefix, ''),
    coalesce(app_claims, convert_to(jsonb_build_object('roles', ` + legacyList("roles") + `, 'scopes', ` +
	legacyList("scopes") + `, 'groups', ` + legacyList("groups") + `)::text, 'UTF8')),
    created_epoch, created_at, expires_at, revoked_at`

func scanAPIKey(row scanner) (contract.APIKey, error) {
	var (
		k                  contract.APIKey
		id                 *uuid.UUID
		tenant, hash       string
		expires, revokedAt *time.Time
	)
	if err := row.Scan(&id, &tenant, &k.Owner.User, &hash, &k.Kind, &k.Name, &k.AppClaims, &k.CreatedEpoch,
		&k.CreatedAt, &expires, &revokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return k, store.ErrNotFound
		}
		return k, errors.Join(errors.New("tokens: read api key"), err)
	}
	t, err := tenantOf(tenant)
	if err != nil {
		return k, errors.Join(contract.ErrInvalidRecord, err)
	}
	if k.KeyHash, err = hex.DecodeString(hash); err != nil {
		return k, errors.Join(contract.ErrInvalidRecord, err)
	}
	if id != nil {
		k.ID = *id
	}
	k.Owner.Tenant = t
	k.AppClaims = nonEmpty(k.AppClaims)
	k.CreatedAt = k.CreatedAt.UTC()
	if expires != nil {
		k.ExpiresAt = expires.UTC()
	}
	if revokedAt != nil {
		k.RevokedAt = revokedAt.UTC()
	}
	return k, nil
}

func (s *Store) GetAPIKey(ctx context.Context, t principal.TenantID, keyHash []byte) (contract.APIKey, error) {
	return scanAPIKey(s.db.QueryRow(ctx, `SELECT `+apiKeyColumns+` FROM tokens
WHERE tenant_id = $1 AND token_hash = $2 AND claims IS NOT NULL AND (expires_at IS NULL OR expires_at > statement_timestamp())`,
		t.String(), hex.EncodeToString(keyHash)))
}

func (s *Store) ListAPIKeys(ctx context.Context, owner principal.Subject) ([]contract.APIKey, error) {
	rows, err := s.db.Query(ctx, `SELECT `+apiKeyColumns+` FROM tokens
WHERE tenant_id = $1 AND claims IS NOT NULL AND `+ownedBy("$2")+`
ORDER BY created_at, id`, owner.Tenant.String(), owner.User)
	if err != nil {
		return nil, errors.Join(errors.New("tokens: list api keys"), err)
	}
	defer rows.Close()
	out := []contract.APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("tokens: list api keys"), err)
	}
	return out, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, owner principal.Subject, id uuid.UUID) error {
	var exists bool
	err := s.db.QueryRow(ctx, `WITH hit AS (
    UPDATE tokens SET revoked_at = statement_timestamp()
    WHERE id = $1 AND tenant_id = $2 AND claims IS NOT NULL AND revoked_at IS NULL AND `+ownedBy("$3")+`
    RETURNING 1)
SELECT EXISTS (SELECT 1 FROM hit)
    OR EXISTS (SELECT 1 FROM tokens WHERE id = $1 AND tenant_id = $2 AND claims IS NOT NULL AND `+ownedBy("$3")+`)`,
		id, owner.Tenant.String(), owner.User).Scan(&exists)
	if err != nil {
		return errors.Join(errors.New("tokens: revoke api key"), err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}

func tenantOf(s string) (principal.TenantID, error) {
	if s == "" {
		return principal.TenantID{}, nil
	}
	t, err := principal.ParseTenantID(s)
	if err != nil {
		return principal.TenantID{}, errors.Join(errors.New("tokens: stored tenant"), err)
	}
	return t, nil
}
