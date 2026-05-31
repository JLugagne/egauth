// Package pgxmigrate provides the shared migration runner used by every pgx-backed store in
// libauth (sessions, identity, tokens, mfa, otp, passkey). Each store keeps its own embedded
// migrations/*.sql directory and a one-line Migrate delegate; the versioning logic lives here
// so it is defined and tested once.
//
// Migration contract (callers and migration authors MUST honor this):
//   - Files are named NNN_description.sql with a zero-padded numeric prefix; they apply in
//     filename (lexical == numeric) order. Once a file has been applied (recorded in
//     schema_migrations) its content MUST NOT be edited — add a new NNN_ file instead. There
//     is no per-file checksum, so an edit to an already-applied file is silently skipped.
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
package pgxmigrate

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the minimal executor Run needs. It is satisfied structurally by *pgxpool.Pool,
// pgx.Tx, and every store package's own DBQuerier, so callers pass their existing handle with
// no conversion.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Run applies every migrations/*.sql file in fsys that has not yet been recorded in the
// schema_migrations table, in filename order. Re-running after every file has applied is a
// no-op: each already-recorded file is skipped without being re-executed. See the package doc
// for the migration-authoring contract.
func Run(ctx context.Context, db Querier, fsys fs.FS) error {
	if _, err := db.Exec(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("pgxmigrate: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return fmt.Errorf("pgxmigrate: read migrations dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version := entry.Name()

		var applied bool
		if err := db.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("pgxmigrate: check %q: %w", version, err)
		}
		if applied {
			continue
		}

		content, err := fs.ReadFile(fsys, "migrations/"+version)
		if err != nil {
			return fmt.Errorf("pgxmigrate: read %q: %w", version, err)
		}

		// Record the version in the SAME Exec as the migration body. With no bind arguments
		// pgx uses the simple query protocol, under which Postgres wraps the whole
		// multi-statement string in one implicit transaction — so the DDL and the version row
		// commit atomically even when db is a bare pool that cannot open a transaction for us.
		// The version is a build-time-embedded filename, but escape quotes defensively since it
		// is interpolated as a SQL literal (a bound $1 would force the extended protocol and
		// forbid the multi-statement string).
		sql := string(content) + "\nINSERT INTO schema_migrations (version) VALUES ('" +
			strings.ReplaceAll(version, "'", "''") + "') ON CONFLICT (version) DO NOTHING;"
		if _, err := db.Exec(ctx, sql); err != nil {
			return fmt.Errorf("pgxmigrate: apply %q: %w", version, err)
		}
	}
	return nil
}

const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`
