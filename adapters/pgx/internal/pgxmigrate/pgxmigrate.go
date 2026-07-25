// Package pgxmigrate provides the shared migration runner used by every pgx-backed store in
// egauth (sessions, identity, tokens, mfa, otp, passkey). Each store keeps its own embedded
// migrations/*.sql directory and a one-line Migrate delegate; the versioning logic lives here
// so it is defined and tested once.
//
// Migration contract (callers and migration authors MUST honor this):
//   - Files are named NNN_description.sql with a zero-padded numeric prefix; they apply in
//     filename (lexical == numeric) order. Once a file has been applied (recorded in
//     schema_migrations) its content MUST NOT be edited — add a new NNN_ file instead. There
//     is no per-file checksum, so an edit to an already-applied file is silently skipped.
//   - Every store shares ONE schema_migrations table, so a version is recorded as
//     "<namespace>:<filename>", never the bare filename: two stores may legitimately ship the
//     same filename (sessions and otp both have 002_add_expires_at_index.sql), and keying on the
//     filename alone made the second store's file look already-applied and silently skipped it,
//     leaving that store's schema incomplete. Namespaces must therefore be unique per store and
//     must not contain versionSeparator.
//   - Upgrading from a build that recorded bare filenames re-applies every file once, because no
//     namespaced row exists yet. That is safe (every file is idempotent) and is what repairs a
//     schema whose migration was previously skipped by a filename collision.
//   - Each file MUST be idempotent (CREATE ... IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, ...).
//     Run cannot open its own transaction (the Querier it is given may be a bare connection
//     pool with autocommit-per-statement), so the version table is a re-run OPTIMIZATION, not
//     a crash-safe exactly-once guarantee: if the process dies after a file applies but before
//     its version row is durable, the file re-applies on the next run — which is harmless only
//     because it is idempotent.
//   - Each file MUST be runnable inside a single implicit transaction: no CREATE INDEX
//     CONCURRENTLY, no VACUUM, and no explicit BEGIN/COMMIT. Run appends the version-recording
//     INSERT to the file's SQL and executes both in one Exec; under the simple query protocol
//     Postgres wraps that whole string in one implicit transaction, so the DDL and the version
//     row commit or roll back together even on a bare pool. A transaction-control or
//     CONCURRENTLY statement would break that wrapping.
//   - Run takes a Postgres advisory lock keyed on the caller-supplied namespace for the whole
//     migration run (see lockKeyForNamespace), so concurrent Migrate calls targeting the SAME
//     namespace (e.g. N replicas of one service starting together during a rolling deploy)
//     serialise instead of racing: even fully idempotent "IF NOT EXISTS" DDL is not safe against
//     a concurrent identical DDL statement in Postgres (a well-known catalog race), so the lock
//     is required, not just an optimization. Callers targeting DIFFERENT namespaces never
//     contend with each other.
package pgxmigrate

import (
	"context"
	"errors"
	"hash/fnv"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal executor Run needs. It is satisfied structurally by *pgxpool.Pool,
// pgx.Tx, and every store package's own DBQuerier, so callers pass their existing handle with
// no conversion.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// pooler is satisfied by *pgxpool.Pool. Run type-asserts for it so it can Acquire a single
// dedicated connection to hold the session-level advisory lock on: pg_advisory_lock is bound to
// the backend connection that took it, so a bare pool (whose Exec/QueryRow may each hop to a
// different physical connection) cannot be used directly to lock-then-unlock, and letting the
// "locked" connection go back to the pool mid-run would let another goroutine borrow it.
type pooler interface {
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
}

// Run applies every migrations/*.sql file in fsys that has not yet been recorded in the
// schema_migrations table, in filename order, holding a Postgres advisory lock derived from
// namespace for the whole run. Re-running after every file has applied is a no-op: each
// already-recorded file is skipped without being re-executed. See the package doc for the
// migration-authoring and locking contract.
func Run(ctx context.Context, db Querier, fsys fs.FS, namespace string) error {
	if pool, ok := db.(pooler); ok {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return errors.Join(errors.New("pgxmigrate: acquire connection"), err)
		}
		defer conn.Release()
		db = conn
	}

	lockKey := lockKeyForNamespace(namespace)
	if _, err := db.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return errors.Join(errors.New("pgxmigrate: acquire advisory lock"), err)
	}
	defer func() {
		_, _ = db.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockKey)
	}()

	if _, err := db.Exec(ctx, createSchemaMigrations); err != nil {
		return errors.Join(errors.New("pgxmigrate: create schema_migrations"), err)
	}

	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return errors.Join(errors.New("pgxmigrate: read migrations dir"), err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		version := namespace + versionSeparator + filename

		var applied bool
		if err := db.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version,
		).Scan(&applied); err != nil {
			return errors.Join(errors.New("pgxmigrate: check "+version), err)
		}
		if applied {
			continue
		}

		content, err := fs.ReadFile(fsys, "migrations/"+filename)
		if err != nil {
			return errors.Join(errors.New("pgxmigrate: read "+version), err)
		}

		// Record the version in the SAME Exec as the migration body. With no bind arguments
		// pgx uses the simple query protocol, under which Postgres wraps the whole
		// multi-statement string in one implicit transaction — so the DDL and the version row
		// commit atomically even when db is a bare pool that cannot open a transaction for us.
		// The version is a caller-supplied namespace plus a build-time-embedded filename, but
		// escape quotes defensively since it is interpolated as a SQL literal (a bound $1 would
		// force the extended protocol and forbid the multi-statement string).
		sql := string(content) + "\nINSERT INTO schema_migrations (version) VALUES ('" +
			strings.ReplaceAll(version, "'", "''") + "') ON CONFLICT (version) DO NOTHING;"
		if _, err := db.Exec(ctx, sql); err != nil {
			return errors.Join(errors.New("pgxmigrate: apply "+version), err)
		}
	}
	return nil
}

// lockKeyForNamespace derives the stable pg_advisory_lock key for a migration namespace. It is a
// deterministic FNV-1a hash of namespace, so the same namespace always yields the same key
// (required for concurrent callers to actually contend on the same lock) regardless of which
// migration files a given build embeds — the key must NOT depend on file contents/names, since
// during a rolling deploy the old and new replica embed different file sets and must still
// serialise against each other.
func lockKeyForNamespace(namespace string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(namespace))
	return int64(h.Sum64()) //#nosec G115 -- reinterpreted as an opaque pg_advisory_lock key; any bit pattern (incl. negative) is a valid lock ID, no value semantics are lost
}

// versionSeparator joins the migration namespace and the filename into the schema_migrations
// primary key. It must not appear in any namespace, so that the composite key is unambiguous.
const versionSeparator = ":"

const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`
