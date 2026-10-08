// Package ceremony is the PostgreSQL ceremony.Store. Records and single-use marks of stateless
// handles live in egauth_ceremonies and egauth_ceremony_consumed and are shared by every instance.
package ceremony

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/ceremony"
)

// Migrations holds the schema of the store; pgxstore registers it as module "ceremony".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const moduleName = "ceremony"

// Store is safe for concurrent use. Every timestamp comes from the database clock.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("ceremony: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"egauth_ceremonies", "egauth_ceremony_consumed"} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, t.String()); err != nil {
				return errors.Join(errors.New("ceremony: erase tenant"), err)
			}
		}
		return nil
	})
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	var total int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"egauth_ceremonies", "egauth_ceremony_consumed"} {
			tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE expires_at <= now()`)
			if err != nil {
				return errors.Join(errors.New("ceremony: reap expired"), err)
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

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("ceremony: begin"), err)
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, rollback(ctx, tx))
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("ceremony: commit"), err)
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func scopeLock(t principal.TenantID, k contract.Kind, scope []byte) string {
	return fmt.Sprintf("egauth/ceremony/%s/%d/%x", t.String(), k, scope)
}

func kindLock(t principal.TenantID, k contract.Kind) string {
	return fmt.Sprintf("egauth/ceremony/%s/%d", t.String(), k)
}

const (
	lockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

	deleteLapsedSQL = `DELETE FROM egauth_ceremonies
WHERE tenant_id = $1 AND kind = $2 AND handle_hash = $3 AND expires_at <= now()`

	insertSQL = `INSERT INTO egauth_ceremonies
    (tenant_id, kind, handle_hash, scope_hash, sealed, payload, attempts, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, kind, handle_hash) DO NOTHING`

	evictScopeSQL = `DELETE FROM egauth_ceremonies
WHERE (tenant_id, kind, handle_hash) IN (
    SELECT tenant_id, kind, handle_hash FROM egauth_ceremonies
    WHERE tenant_id = $1 AND kind = $2 AND scope_hash = $3 AND expires_at > now() AND handle_hash <> $4
    ORDER BY created_at DESC, handle_hash DESC
    OFFSET $5)`

	evictKindSQL = `DELETE FROM egauth_ceremonies
WHERE (tenant_id, kind, handle_hash) IN (
    SELECT tenant_id, kind, handle_hash FROM egauth_ceremonies
    WHERE tenant_id = $1 AND kind = $2 AND expires_at > now() AND handle_hash <> $3
    ORDER BY created_at DESC, handle_hash DESC
    OFFSET $4)`
)

func (s *Store) Put(ctx context.Context, r contract.Record) (int, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}
	evicted := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tenant, kind, handle := r.Tenant().String(), int16(r.Kind()), r.HandleHash()
		payload := append([]byte{}, r.Payload()...)
		ceiling := r.Kind().MaxLivePerTenant()
		if _, err := tx.Exec(ctx, lockSQL, scopeLock(r.Tenant(), r.Kind(), r.ScopeHash())); err != nil {
			return errors.Join(errors.New("ceremony: lock scope"), err)
		}
		if ceiling > 0 {
			if _, err := tx.Exec(ctx, lockSQL, kindLock(r.Tenant(), r.Kind())); err != nil {
				return errors.Join(errors.New("ceremony: lock kind"), err)
			}
		}
		if _, err := tx.Exec(ctx, deleteLapsedSQL, tenant, kind, handle); err != nil {
			return errors.Join(errors.New("ceremony: drop lapsed duplicate"), err)
		}
		tag, err := tx.Exec(ctx, insertSQL, tenant, kind, handle, r.ScopeHash(), r.Pending.Bytes(), payload,
			r.Attempts(), r.ExpiresAt(), r.CreatedAt())
		if err != nil {
			return errors.Join(errors.New("ceremony: insert"), err)
		}
		if tag.RowsAffected() == 0 {
			return store.ErrConflict
		}
		if limit := r.Kind().MaxLivePerScope(); limit > 0 {
			tag, err := tx.Exec(ctx, evictScopeSQL, tenant, kind, r.ScopeHash(), handle, limit-1)
			if err != nil {
				return errors.Join(errors.New("ceremony: evict scope"), err)
			}
			evicted += int(tag.RowsAffected())
		}
		if ceiling > 0 {
			tag, err := tx.Exec(ctx, evictKindSQL, tenant, kind, handle, ceiling-1)
			if err != nil {
				return errors.Join(errors.New("ceremony: evict kind"), err)
			}
			evicted += int(tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return evicted, nil
}

func checkHandle(h []byte) error {
	if len(h) < contract.HandleHashLen {
		return contract.ErrHandleTooShort
	}
	return nil
}

const columns = `scope_hash, sealed, payload, attempts, expires_at, created_at`

type scanner interface{ Scan(dest ...any) error }

func restore(row scanner, t principal.TenantID, k contract.Kind, handle []byte) (contract.Record, error) {
	r := contract.Row{Tenant: t, Kind: k, HandleHash: handle}
	var sealed []byte
	if err := row.Scan(&r.ScopeHash, &sealed, &r.Payload, &r.Attempts, &r.ExpiresAt, &r.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return contract.Record{}, store.ErrNotFound
		}
		return contract.Record{}, errors.Join(errors.New("ceremony: read record"), err)
	}
	r.Pending = principal.SealedFromBytes(sealed)
	return contract.Restore(r)
}

func (s *Store) Peek(ctx context.Context, t principal.TenantID, k contract.Kind, handleHash []byte) (contract.Record, error) {
	if err := checkHandle(handleHash); err != nil {
		return contract.Record{}, err
	}
	row := s.db.QueryRow(ctx, `SELECT `+columns+` FROM egauth_ceremonies
WHERE tenant_id = $1 AND kind = $2 AND handle_hash = $3 AND expires_at > now()`, t.String(), int16(k), handleHash)
	return restore(row, t, k, handleHash)
}

func (s *Store) Consume(ctx context.Context, t principal.TenantID, k contract.Kind, handleHash []byte) (contract.Record, error) {
	if err := checkHandle(handleHash); err != nil {
		return contract.Record{}, err
	}
	row := s.db.QueryRow(ctx, `DELETE FROM egauth_ceremonies
WHERE tenant_id = $1 AND kind = $2 AND handle_hash = $3 AND expires_at > now()
RETURNING `+columns, t.String(), int16(k), handleHash)
	return restore(row, t, k, handleHash)
}

func (s *Store) RecordFailure(ctx context.Context, t principal.TenantID, k contract.Kind, handleHash []byte) (int, error) {
	if err := checkHandle(handleHash); err != nil {
		return 0, err
	}
	remaining := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var attempts int
		err := tx.QueryRow(ctx, `UPDATE egauth_ceremonies SET attempts = attempts + 1
WHERE tenant_id = $1 AND kind = $2 AND handle_hash = $3 AND expires_at > now()
RETURNING attempts`, t.String(), int16(k), handleHash).Scan(&attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return errors.Join(errors.New("ceremony: record failure"), err)
		}
		remaining = max(k.MaxAttempts()-attempts, 0)
		if remaining > 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM egauth_ceremonies WHERE tenant_id = $1 AND kind = $2 AND handle_hash = $3`,
			t.String(), int16(k), handleHash); err != nil {
			return errors.Join(errors.New("ceremony: delete exhausted record"), err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

func (s *Store) MarkConsumed(ctx context.Context, t principal.TenantID, k contract.Kind, handleHash []byte, until time.Time) (bool, error) {
	if !k.Valid() {
		return false, errors.Join(contract.ErrInvalidRecord, errors.New("invalid kind"))
	}
	if !k.Stateless() {
		return false, contract.ErrStoredKind
	}
	if err := checkHandle(handleHash); err != nil {
		return false, err
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO egauth_ceremony_consumed (tenant_id, kind, handle_hash, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, kind, handle_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
WHERE egauth_ceremony_consumed.expires_at <= now()`, t.String(), int16(k), handleHash, until)
	if err != nil {
		return false, errors.Join(errors.New("ceremony: mark consumed"), err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) DeleteForScope(ctx context.Context, t principal.TenantID, scopeHash []byte, kinds ...contract.Kind) (int64, error) {
	if len(scopeHash) == 0 {
		return 0, nil
	}
	filter := make([]int16, 0, len(kinds))
	for _, k := range kinds {
		filter = append(filter, int16(k))
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM egauth_ceremonies
WHERE tenant_id = $1 AND scope_hash = $2 AND (cardinality($3::smallint[]) = 0 OR kind = ANY($3::smallint[]))`,
		t.String(), scopeHash, filter)
	if err != nil {
		return 0, errors.Join(errors.New("ceremony: delete for scope"), err)
	}
	return tag.RowsAffected(), nil
}
