// Package keys is the PostgreSQL keys.Store. Keys live in the v0.16 keystore_keys table, extended in
// place by 003_kek_v1.sql; tombstones and the change feed live in egauth_tenant_tombstones and
// egauth_key_changes.
package keys

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/keys"
)

// Migrations holds the schema of the store; pgxstore registers it as module "keys". Files 001 and
// 002 are the v0.16 keystore files under their v0.16 names, so a v0.16 database skips them.
//
// Beyond the DESIGN section 4.9 list, 003 adds a unique seq identity on keystore_keys (the stable
// cursor of V016Sealed), a partial not_after index for ReapExpired, and egauth_key_feed_horizon, which
// records the pruned feed position so ChangesSince reports a gap instead of skipping changes. All are
// expand-only and idempotent.
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const (
	moduleName    = "keys"
	feedPage      = 1000
	feedRetention = 24 * time.Hour
	lockTenantSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
	lockFeedSQL   = `SELECT pg_advisory_xact_lock(hashtextextended('egauth/keys/changes', 0))`
	keyColumns    = `tenant_id, key_id, alg, secret, aad_version, created_at, not_after, retired_at`
	signerWhere   = `WHERE tenant_id = $1 AND retired_at IS NULL AND (not_after IS NULL OR not_after > now())
ORDER BY created_at DESC, key_id COLLATE "C" DESC LIMIT 1`
)

var (
	errInvalidKey   = errors.New("keys: invalid key")
	errInvalidLimit = errors.New("keys: limit must be positive")
	errInvalidSeal  = errors.New("keys: invalid reseal")
	errFeedGap      = errors.New("keys: cursor is older than the retained change feed; drop the key caches and resume from the zero cursor")
)

// Store is safe for concurrent use. Every expiry decision reads the database clock. Writes to one
// tenant serialise on a per-tenant advisory lock, so the tombstone check and the insert it guards are
// atomic (T-13). Feed rows are appended under one feed lock taken last and held until commit, so
// feed positions follow commit order and a poller never skips a change that commits late (T-15).
//
// ReapExpired prunes feed rows older than a day and records the last pruned position in
// egauth_key_feed_horizon. ChangesSince with a non-zero cursor older than that position returns an
// error wrapping store.ErrNotFound instead of a feed with a silent gap: the poller must drop its key
// caches and resume from the zero cursor.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("keys: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("keys: begin"), err)
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, rollback(ctx, tx))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("keys: commit"), err)
	}
	return nil
}

func record(ctx context.Context, tx pgx.Tx, tenants ...principal.TenantID) error {
	if len(tenants) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, lockFeedSQL); err != nil {
		return errors.Join(errors.New("keys: lock change feed"), err)
	}
	for _, t := range tenants {
		if _, err := tx.Exec(ctx, `INSERT INTO egauth_key_changes (tenant_id, created_at) VALUES ($1, now())`, t.String()); err != nil {
			return errors.Join(errors.New("keys: append change"), err)
		}
	}
	return nil
}

func (s *Store) mutate(ctx context.Context, t principal.TenantID, fn func(pgx.Tx) (bool, error)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockTenantSQL, "egauth/keys/tenant/"+t.String()); err != nil {
			return errors.Join(errors.New("keys: lock tenant"), err)
		}
		changed, err := fn(tx)
		if err != nil || !changed {
			return err
		}
		return record(ctx, tx, t)
	})
}

func tombstoned(ctx context.Context, q migrate.Querier, t principal.TenantID) (bool, error) {
	var dead bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM egauth_tenant_tombstones WHERE tenant_id = $1)`, t.String()).Scan(&dead); err != nil {
		return false, errors.Join(errors.New("keys: read tombstone"), err)
	}
	return dead, nil
}

func refuseTombstoned(ctx context.Context, tx pgx.Tx, t principal.TenantID) error {
	dead, err := tombstoned(ctx, tx, t)
	if err != nil {
		return err
	}
	if dead {
		return contract.ErrTenantTombstoned
	}
	return nil
}

func checkKey(k contract.Key) error {
	if k.AADVersion != contract.AADVersionCurrent {
		return contract.ErrLegacyAADVersion
	}
	if k.KeyID == "" || k.Alg == "" || len(k.Sealed) == 0 {
		return errInvalidKey
	}
	return nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC().Truncate(time.Microsecond)
	return &u
}

func nullTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return nullTime(*t)
}

func insertKey(ctx context.Context, tx pgx.Tx, k contract.Key) error {
	tag, err := tx.Exec(ctx, `INSERT INTO keystore_keys (tenant_id, key_id, alg, secret, aad_version, created_at, not_after, retired_at)
VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, now()), $7, $8)
ON CONFLICT (tenant_id, key_id) DO NOTHING`,
		k.Tenant.String(), k.KeyID, k.Alg, bytes.Clone(k.Sealed), int16(k.AADVersion),
		nullTime(k.CreatedAt), nullTime(k.NotAfter), nullTimePtr(k.RetiredAt))
	if err != nil {
		return errors.Join(errors.New("keys: insert key"), err)
	}
	if tag.RowsAffected() == 0 {
		return errors.Join(store.ErrConflict, errors.New("keys: key id exists in the tenant"))
	}
	return nil
}

func (s *Store) CreateTenant(ctx context.Context, initial contract.Key) error {
	if err := checkKey(initial); err != nil {
		return err
	}
	return s.mutate(ctx, initial.Tenant, func(tx pgx.Tx) (bool, error) {
		if err := refuseTombstoned(ctx, tx, initial.Tenant); err != nil {
			return false, err
		}
		exists, err := tenantExists(ctx, tx, initial.Tenant)
		if err != nil {
			return false, err
		}
		if exists {
			return false, errors.Join(store.ErrConflict, errors.New("keys: tenant already provisioned"))
		}
		return true, insertKey(ctx, tx, initial)
	})
}

func tenantExists(ctx context.Context, q migrate.Querier, t principal.TenantID) (bool, error) {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM keystore_keys WHERE tenant_id = $1)`, t.String()).Scan(&ok); err != nil {
		return false, errors.Join(errors.New("keys: read tenant"), err)
	}
	return ok, nil
}

func (s *Store) TenantExists(ctx context.Context, t principal.TenantID) (bool, error) {
	return tenantExists(ctx, s.db, t)
}

func (s *Store) PutKey(ctx context.Context, k contract.Key) error {
	if err := checkKey(k); err != nil {
		return err
	}
	return s.mutate(ctx, k.Tenant, func(tx pgx.Tx) (bool, error) {
		if err := refuseTombstoned(ctx, tx, k.Tenant); err != nil {
			return false, err
		}
		return true, insertKey(ctx, tx, k)
	})
}

func scanKey(row pgx.Row) (contract.Key, error) {
	var (
		k                 contract.Key
		tenant            string
		aad               int16
		notAfter, retired *time.Time
	)
	if err := row.Scan(&tenant, &k.KeyID, &k.Alg, &k.Sealed, &aad, &k.CreatedAt, &notAfter, &retired); err != nil {
		return contract.Key{}, err
	}
	t, err := tenantOf(tenant)
	if err != nil {
		return contract.Key{}, err
	}
	if aad < 0 || aad > 255 {
		return contract.Key{}, errors.New("keys: stored aad_version out of range")
	}
	k.Tenant, k.AADVersion, k.CreatedAt = t, uint8(aad), k.CreatedAt.UTC()
	if notAfter != nil {
		k.NotAfter = notAfter.UTC()
	}
	if retired != nil {
		r := retired.UTC()
		k.RetiredAt = &r
	}
	return k, nil
}

func tenantOf(s string) (principal.TenantID, error) {
	if s == "" {
		return principal.TenantID{}, nil
	}
	t, err := principal.ParseTenantID(s)
	if err != nil {
		return principal.TenantID{}, errors.Join(errors.New("keys: stored tenant"), err)
	}
	return t, nil
}

func (s *Store) ActiveKey(ctx context.Context, t principal.TenantID) (contract.Key, error) {
	k, err := scanKey(s.db.QueryRow(ctx, `SELECT `+keyColumns+` FROM keystore_keys `+signerWhere, t.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return contract.Key{}, contract.ErrNoActiveKey
	}
	if err != nil {
		return contract.Key{}, errors.Join(errors.New("keys: read active key"), err)
	}
	return k, nil
}

func (s *Store) VerificationKeys(ctx context.Context, t principal.TenantID) ([]contract.Key, error) {
	rows, err := s.db.Query(ctx, `SELECT `+keyColumns+` FROM keystore_keys
WHERE tenant_id = $1 AND NOT (retired_at IS NOT NULL AND not_after IS NULL)
  AND (not_after IS NULL OR not_after > now())
ORDER BY created_at DESC, key_id COLLATE "C" DESC`, t.String())
	if err != nil {
		return nil, errors.Join(errors.New("keys: read verification keys"), err)
	}
	defer rows.Close()
	out := []contract.Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, errors.Join(errors.New("keys: read verification keys"), err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("keys: read verification keys"), err)
	}
	return out, nil
}

func (s *Store) Rotate(ctx context.Context, r contract.Rotation) error {
	if !r.Valid() {
		return contract.ErrInvalidRotation
	}
	if err := checkKey(r.Next); err != nil {
		return errors.Join(contract.ErrInvalidRotation, err)
	}
	return s.mutate(ctx, r.Next.Tenant, func(tx pgx.Tx) (bool, error) {
		if err := refuseTombstoned(ctx, tx, r.Next.Tenant); err != nil {
			return false, err
		}
		signer, err := signerID(ctx, tx, r.Next.Tenant)
		if err != nil {
			return false, err
		}
		if signer != r.Previous {
			return false, errors.Join(store.ErrConflict, errors.New("keys: previous key is not the tenant's active signer"))
		}
		tag, err := tx.Exec(ctx, `UPDATE keystore_keys
SET retired_at = $3,
    not_after = CASE WHEN not_after IS NULL OR not_after > $4 THEN $4 ELSE not_after END
WHERE tenant_id = $1 AND key_id = $2 AND retired_at IS NULL`,
			r.Next.Tenant.String(), r.Previous, nullTime(r.RetiredAt), nullTime(r.OverlapUntil))
		if err != nil {
			return false, errors.Join(errors.New("keys: retire previous key"), err)
		}
		if tag.RowsAffected() == 0 {
			return false, errors.Join(store.ErrConflict, errors.New("keys: previous key is not the tenant's active signer"))
		}
		if err := insertKey(ctx, tx, r.Next); err != nil {
			return false, err
		}
		if signer, err = signerID(ctx, tx, r.Next.Tenant); err != nil {
			return false, err
		}
		if signer != r.Next.KeyID {
			return false, errors.Join(store.ErrConflict, errors.New("keys: next key would not become the tenant's active signer"))
		}
		return true, nil
	})
}

func signerID(ctx context.Context, tx pgx.Tx, t principal.TenantID) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT key_id FROM keystore_keys `+signerWhere, t.String()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", errors.Join(errors.New("keys: read active key"), err)
	}
	return id, nil
}

func (s *Store) RevokeTenantKeys(ctx context.Context, t principal.TenantID) error {
	return s.mutate(ctx, t, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM keystore_keys WHERE tenant_id = $1`, t.String())
		if err != nil {
			return false, errors.Join(errors.New("keys: revoke tenant keys"), err)
		}
		return tag.RowsAffected() > 0, nil
	})
}

func (s *Store) Tombstone(ctx context.Context, t principal.TenantID) error {
	return s.mutate(ctx, t, func(tx pgx.Tx) (bool, error) {
		erased, err := tx.Exec(ctx, `DELETE FROM keystore_keys WHERE tenant_id = $1`, t.String())
		if err != nil {
			return false, errors.Join(errors.New("keys: erase tenant keys"), err)
		}
		marked, err := tx.Exec(ctx, `INSERT INTO egauth_tenant_tombstones (tenant_id, erased_at) VALUES ($1, now())
ON CONFLICT (tenant_id) DO NOTHING`, t.String())
		if err != nil {
			return false, errors.Join(errors.New("keys: write tombstone"), err)
		}
		return erased.RowsAffected() > 0 || marked.RowsAffected() > 0, nil
	})
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.Tombstone(ctx, t)
}

func (s *Store) IsTombstoned(ctx context.Context, t principal.TenantID) (bool, error) {
	return tombstoned(ctx, s.db, t)
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `DELETE FROM keystore_keys
WHERE (not_after IS NOT NULL AND not_after <= now()) OR (retired_at IS NOT NULL AND not_after IS NULL)
RETURNING tenant_id`)
		if err != nil {
			return errors.Join(errors.New("keys: reap expired"), err)
		}
		seen := map[string]struct{}{}
		var names []string
		for rows.Next() {
			var tenant string
			if err := rows.Scan(&tenant); err != nil {
				rows.Close()
				return errors.Join(errors.New("keys: reap expired"), err)
			}
			n++
			if _, dup := seen[tenant]; !dup {
				seen[tenant] = struct{}{}
				names = append(names, tenant)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return errors.Join(errors.New("keys: reap expired"), err)
		}
		slices.Sort(names)
		tenants := make([]principal.TenantID, 0, len(names))
		for _, name := range names {
			t, err := tenantOf(name)
			if err != nil {
				return err
			}
			tenants = append(tenants, t)
		}
		if err := record(ctx, tx, tenants...); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH gone AS (
    DELETE FROM egauth_key_changes WHERE created_at < now() - $1::bigint * interval '1 microsecond' RETURNING seq
)
INSERT INTO egauth_key_feed_horizon (id, pruned_through)
SELECT 1, max(seq) FROM gone HAVING count(*) > 0
ON CONFLICT (id) DO UPDATE
SET pruned_through = GREATEST(egauth_key_feed_horizon.pruned_through, EXCLUDED.pruned_through)`,
			feedRetention.Microseconds()); err != nil {
			return errors.Join(errors.New("keys: prune change feed"), err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) ChangesSince(ctx context.Context, c store.Cursor) ([]contract.Change, store.Cursor, error) {
	if c.Position() > uint64(1<<63-1) {
		return []contract.Change{}, c, nil
	}
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id FROM egauth_key_changes WHERE seq > $1 ORDER BY seq LIMIT $2`,
		int64(c.Position()), feedPage)
	if err != nil {
		return nil, c, errors.Join(errors.New("keys: read change feed"), err)
	}
	defer rows.Close()
	out := []contract.Change{}
	seen := map[string]struct{}{}
	last := c.Position()
	for rows.Next() {
		var (
			seq    int64
			tenant string
		)
		if err := rows.Scan(&seq, &tenant); err != nil {
			return nil, c, errors.Join(errors.New("keys: read change feed"), err)
		}
		last = uint64(max(seq, 0))
		if _, dup := seen[tenant]; dup {
			continue
		}
		seen[tenant] = struct{}{}
		t, err := tenantOf(tenant)
		if err != nil {
			return nil, c, err
		}
		out = append(out, contract.Change{Tenant: t})
	}
	if err := rows.Err(); err != nil {
		return nil, c, errors.Join(errors.New("keys: read change feed"), err)
	}
	if err := s.checkHorizon(ctx, c); err != nil {
		return nil, c, err
	}
	return out, store.RestoreCursor(last), nil
}

func (s *Store) checkHorizon(ctx context.Context, c store.Cursor) error {
	if c.IsZero() {
		return nil
	}
	var pruned int64
	err := s.db.QueryRow(ctx, `SELECT pruned_through FROM egauth_key_feed_horizon WHERE id = 1`).Scan(&pruned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errors.Join(errors.New("keys: read change feed horizon"), err)
	}
	if c.Position() < uint64(max(pruned, 0)) {
		return errors.Join(store.ErrNotFound, errFeedGap)
	}
	return nil
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM keystore_keys WHERE aad_version = $1`,
		int16(contract.AADVersionLegacy)).Scan(&n); err != nil {
		return 0, errors.Join(errors.New("keys: count legacy keys"), err)
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]contract.V016Row, store.Cursor, error) {
	if limit < 1 {
		return nil, after, errInvalidLimit
	}
	if after.Position() > uint64(1<<63-1) {
		return []contract.V016Row{}, after, nil
	}
	rows, err := s.db.Query(ctx, `SELECT seq, tenant_id, key_id, secret FROM keystore_keys
WHERE aad_version = $1 AND seq > $2 ORDER BY seq LIMIT $3`, int16(contract.AADVersionLegacy), int64(after.Position()), limit)
	if err != nil {
		return nil, after, errors.Join(errors.New("keys: list legacy keys"), err)
	}
	defer rows.Close()
	out := []contract.V016Row{}
	last := after.Position()
	for rows.Next() {
		var (
			seq    int64
			tenant string
			r      contract.V016Row
		)
		if err := rows.Scan(&seq, &tenant, &r.Ref.KeyID, &r.Sealed); err != nil {
			return nil, after, errors.Join(errors.New("keys: list legacy keys"), err)
		}
		if r.Ref.Tenant, err = tenantOf(tenant); err != nil {
			return nil, after, err
		}
		out = append(out, r)
		last = uint64(max(seq, 0))
	}
	if err := rows.Err(); err != nil {
		return nil, after, errors.Join(errors.New("keys: list legacy keys"), err)
	}
	return out, store.RestoreCursor(last), nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r contract.Reseal) (bool, error) {
	if len(r.Old) == 0 || len(r.New) == 0 || r.Ref.KeyID == "" {
		return false, errInvalidSeal
	}
	tag, err := s.db.Exec(ctx, `UPDATE keystore_keys SET secret = $3, aad_version = $5
WHERE tenant_id = $1 AND key_id = $2 AND secret = $4`,
		r.Ref.Tenant.String(), r.Ref.KeyID, bytes.Clone(r.New), r.Old, int16(contract.AADVersionCurrent))
	if err != nil {
		return false, errors.Join(errors.New("keys: replace sealed key"), err)
	}
	return tag.RowsAffected() == 1, nil
}
