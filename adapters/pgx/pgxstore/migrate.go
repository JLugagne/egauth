package pgxstore

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
)

// MigrationDB is the handle Migrate needs; *pgxpool.Pool, *pgx.Conn and pgx.Tx satisfy it.
type MigrationDB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Migrate brings the schema of every store module up to date and takes no KEK: it never reads or
// rewrites sealed data. Progress is recorded per module and file in egauth_schema_migrations. The
// run is one transaction under a database-wide advisory lock, so instances migrating at the same
// startup serialise, repeated calls are no-ops and a failed call changes nothing. A v0.16
// schema_migrations table (version text, applied_at timestamptz) is only read, to skip the files
// v0.16 already applied, so v0.16 replicas keep working on their own tables during a rollout.
func Migrate(ctx context.Context, db MigrationDB) error {
	return migrate.Run(ctx, db, modules())
}
