// Package limiter is the PostgreSQL limiter.Limiter: one token bucket per limiter.Key.StorageKey in
// an UNLOGGED table, shared by every instance. An UNLOGGED table is emptied by a crash, which only
// refills buckets; the keys are digests, never the identifiers they were derived from.
package limiter

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/limiter"
)

// Migrations holds the schema of the limiter; pgxstore registers it as module "limiter".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Limiter = (*Limiter)(nil)

const (
	moduleName = "limiter"
	attempts   = 3
)

// Limiter is safe for concurrent use. Every bucket is charged in one atomic statement, so concurrent
// callers on several instances never exceed the burst. It enforces the full contract.Class budgets.
type Limiter struct {
	db migrate.DB
}

// New returns a limiter over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Limiter { return &Limiter{db: db} }

func (l *Limiter) Ping(ctx context.Context) error {
	var one int
	if err := l.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("limiter: ping"), err)
	}
	return migrate.Check(ctx, l.db, moduleName, Migrations)
}

func (l *Limiter) Durability() store.Durability { return store.Shared }

func perTenantClasses() []contract.Class {
	var out []contract.Class
	for c := range contract.Class(255) {
		if c.Valid() && c.PerTenant() {
			out = append(out, c)
		}
	}
	return out
}

func prefixEnd(p []byte) []byte {
	end := append([]byte{}, p...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] < 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}

func (l *Limiter) EraseTenant(ctx context.Context, t principal.TenantID) error {
	for _, c := range perTenantClasses() {
		lo := contract.TenantPrefix(c, t)
		if _, err := l.db.Exec(ctx, `DELETE FROM egauth_ratelimit WHERE key >= $1 AND key < $2`, lo, prefixEnd(lo)); err != nil {
			return errors.Join(errors.New("limiter: erase tenant"), err)
		}
	}
	return nil
}

func (l *Limiter) ReapExpired(ctx context.Context) (int64, error) {
	var classes []int32
	var bursts, refills []float64
	for c := range contract.Class(255) {
		if !c.Valid() {
			continue
		}
		b := c.Budget()
		classes = append(classes, int32(c))
		bursts = append(bursts, float64(b.Burst))
		refills = append(refills, b.Refill.Seconds())
	}
	tag, err := l.db.Exec(ctx, `DELETE FROM egauth_ratelimit r
USING unnest($1::int[], $2::double precision[], $3::double precision[]) AS b(class, burst, refill)
WHERE get_byte(r.key, 0) = b.class
  AND r.tokens + GREATEST(EXTRACT(EPOCH FROM (now() - r.updated_at))::double precision, 0) / b.refill >= b.burst`,
		classes, bursts, refills)
	if err != nil {
		return 0, errors.Join(errors.New("limiter: reap expired"), err)
	}
	return tag.RowsAffected(), nil
}

const chargeSQL = `UPDATE egauth_ratelimit r
SET tokens = o.refilled - CASE WHEN o.refilled >= 1 THEN 1 ELSE 0 END,
    updated_at = GREATEST(r.updated_at, now())
FROM (
    SELECT key, LEAST($2::double precision, tokens + GREATEST(EXTRACT(EPOCH FROM (now() - updated_at))::double precision, 0) / $3::double precision) AS refilled
    FROM egauth_ratelimit WHERE key = $1 FOR UPDATE
) o
WHERE r.key = o.key
RETURNING o.refilled >= 1, o.refilled`

const createSQL = `INSERT INTO egauth_ratelimit (key, tokens, updated_at) VALUES ($1, $2::double precision - 1, now())
ON CONFLICT (key) DO NOTHING`

func (l *Limiter) Allow(ctx context.Context, key contract.Key) (contract.Decision, error) {
	if !key.Valid() {
		return contract.Decision{}, errors.New("limiter: invalid key")
	}
	budget := key.Class.Budget()
	sk := key.StorageKey()
	burst, refill := float64(budget.Burst), budget.Refill.Seconds()
	for range attempts {
		var allowed bool
		var refilled float64
		err := l.db.QueryRow(ctx, chargeSQL, sk, burst, refill).Scan(&allowed, &refilled)
		if err == nil {
			return decision(allowed, refilled, budget), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return contract.Decision{}, errors.Join(errors.New("limiter: charge"), err)
		}
		tag, err := l.db.Exec(ctx, createSQL, sk, burst)
		if err != nil {
			return contract.Decision{}, errors.Join(errors.New("limiter: create bucket"), err)
		}
		if tag.RowsAffected() == 1 {
			return contract.Decision{Allowed: true}, nil
		}
	}
	return contract.Decision{}, errors.Join(store.ErrConflict, errors.New("limiter: bucket kept changing"))
}

func decision(allowed bool, refilled float64, b contract.Budget) contract.Decision {
	if allowed {
		return contract.Decision{Allowed: true}
	}
	wait := time.Duration((1 - refilled) * float64(b.Refill))
	return contract.Decision{RetryAfter: min(max(wait, time.Nanosecond), b.Refill)}
}
