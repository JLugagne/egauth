// Package deployment is the PostgreSQL deployment.Store: sealed deployment-wide values in
// egauth_deployment and instance liveness in egauth_instances, shared by every instance.
package deployment

import (
	"bytes"
	"context"
	"embed"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	contract "github.com/JLugagne/egauth/store/deployment"
)

// Migrations holds the schema of the store; pgxstore registers it as module "deployment".
//
//go:embed migrations/*.sql
var Migrations embed.FS

var _ contract.Store = (*Store)(nil)

const moduleName = "deployment"

// Store is safe for concurrent use. Liveness is judged by the database clock, so instances with
// skewed clocks still agree.
type Store struct {
	db migrate.DB
}

// New returns a store over db, typically a *pgxpool.Pool, whose schema Migrate has created.
func New(db migrate.DB) *Store { return &Store{db: db} }

func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return errors.Join(errors.New("deployment: ping"), err)
	}
	return migrate.Check(ctx, s.db, moduleName, Migrations)
}

func (s *Store) Durability() store.Durability { return store.Shared }

func (s *Store) EraseTenant(ctx context.Context, _ principal.TenantID) error { return ctx.Err() }

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM egauth_instances WHERE last_seen_at <= now() - make_interval(secs => $1::double precision)`,
		contract.LivenessWindow.Seconds())
	if err != nil {
		return 0, errors.Join(errors.New("deployment: reap expired"), err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) GetSealed(ctx context.Context, key string) ([]byte, error) {
	var sealed []byte
	err := s.db.QueryRow(ctx, `SELECT sealed FROM egauth_deployment WHERE key = $1`, key).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, errors.Join(errors.New("deployment: get sealed"), err)
	}
	return sealed, nil
}

func (s *Store) PutSealedIfAbsent(ctx context.Context, key string, sealed []byte) (bool, error) {
	if key == "" || len(sealed) == 0 {
		return false, errors.New("deployment: key and sealed value are required")
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO egauth_deployment (key, sealed, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO NOTHING`, key, bytes.Clone(sealed))
	if err != nil {
		return false, errors.Join(errors.New("deployment: put sealed"), err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, key string, r contract.Replacement) (bool, error) {
	if len(r.New) == 0 {
		return false, errors.New("deployment: replacement value is required")
	}
	tag, err := s.db.Exec(ctx, `UPDATE egauth_deployment SET sealed = $3, updated_at = now()
WHERE key = $1 AND sealed = $2`, key, bytes.Clone(r.Old), bytes.Clone(r.New))
	if err != nil {
		return false, errors.Join(errors.New("deployment: replace sealed"), err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM egauth_deployment WHERE key = $1)`, key).Scan(&exists); err != nil {
		return false, errors.Join(errors.New("deployment: check key"), err)
	}
	if !exists {
		return false, store.ErrNotFound
	}
	return false, nil
}

func (s *Store) Heartbeat(ctx context.Context, instance uuid.UUID) ([]contract.Instance, error) {
	if instance == uuid.Nil {
		return nil, errors.New("deployment: instance id is required")
	}
	window := contract.LivenessWindow.Seconds()
	if _, err := s.db.Exec(ctx, `INSERT INTO egauth_instances AS i (instance_id, started_at, last_seen_at)
VALUES ($1, clock_timestamp(), clock_timestamp())
ON CONFLICT (instance_id) DO UPDATE SET
    last_seen_at = EXCLUDED.last_seen_at,
    started_at = CASE
        WHEN i.last_seen_at <= EXCLUDED.last_seen_at - make_interval(secs => $2::double precision) THEN EXCLUDED.started_at
        ELSE i.started_at
    END`, instance, window); err != nil {
		return nil, errors.Join(errors.New("deployment: heartbeat"), err)
	}
	rows, err := s.db.Query(ctx, `SELECT instance_id, started_at, last_seen_at FROM egauth_instances
WHERE last_seen_at > clock_timestamp() - make_interval(secs => $1::double precision)
ORDER BY started_at, instance_id`, window)
	if err != nil {
		return nil, errors.Join(errors.New("deployment: list instances"), err)
	}
	defer rows.Close()
	var out []contract.Instance
	for rows.Next() {
		var in contract.Instance
		if err := rows.Scan(&in.ID, &in.StartedAt, &in.LastSeenAt); err != nil {
			return nil, errors.Join(errors.New("deployment: scan instance"), err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(errors.New("deployment: list instances"), err)
	}
	return out, nil
}
