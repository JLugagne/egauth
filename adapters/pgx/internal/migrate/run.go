package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const migrationsDir = "migrations"

var (
	moduleName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	fileVersion = regexp.MustCompile(`^[0-9A-Za-z_.-]{1,128}\.sql$`)
)

// ErrNotMigrated reports that a module's schema lacks a migration the binary embeds; the joined
// error names the first missing module and version.
var ErrNotMigrated = errors.New("migrate: schema is not migrated")

// ErrInvalidModule reports a module list Run refuses: an empty or malformed name, a duplicate name or
// an unreadable or malformed migration file name.
var ErrInvalidModule = errors.New("migrate: invalid module")

// Querier is the executor Run and Check need. *pgxpool.Pool, pgx.Tx and every store handle satisfy it.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DB is the handle the pgx stores hold: a Querier that can also open transactions and stream rows.
// *pgxpool.Pool satisfies it.
type DB interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const createBookkeeping = `CREATE TABLE IF NOT EXISTS egauth_schema_migrations (
    module     TEXT NOT NULL,
    version    TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (module, version)
);`

const selectApplied = `SELECT coalesce(array_agg(version), '{}'::text[]) FROM egauth_schema_migrations WHERE module = $1`

// Migrator is the handle Run needs: a Querier that can open a transaction. *pgxpool.Pool, *pgx.Conn
// and pgx.Tx satisfy it.
type Migrator interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

const migrationLock int64 = 0x6567617574686d67

const lockSQL = `SELECT pg_advisory_xact_lock($1::bigint)`

// Run applies, per module and in file name order, every migration that egauth_schema_migrations does
// not record, and records it. The whole run is one transaction holding a database-wide advisory
// lock, so concurrent runs from several instances serialise and a failed run leaves no trace. A
// module whose FS is nil is skipped. Files must be idempotent and must not use transaction control.
// A v0.16 schema_migrations table is read once to skip files that v0.16 already applied; see
// bootstrap.
func Run(ctx context.Context, db Migrator, modules []Module) error {
	steps, err := buildPlan(modules)
	if err != nil {
		return err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return errors.Join(errors.New("migrate: begin"), err)
	}
	if err := runLocked(ctx, tx, steps); err != nil {
		if rbErr := tx.Rollback(context.WithoutCancel(ctx)); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			return errors.Join(err, rbErr)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(errors.New("migrate: commit"), err)
	}
	return nil
}

func runLocked(ctx context.Context, db Querier, steps []planned) error {
	if _, err := db.Exec(ctx, lockSQL, migrationLock); err != nil {
		return errors.Join(errors.New("migrate: lock"), err)
	}
	if _, err := db.Exec(ctx, createBookkeeping); err != nil {
		return errors.Join(errors.New("migrate: create egauth_schema_migrations"), err)
	}
	if err := bootstrap(ctx, db, steps); err != nil {
		return err
	}
	for _, m := range steps {
		var applied []string
		if err := db.QueryRow(ctx, selectApplied, m.name).Scan(&applied); err != nil {
			return errors.Join(fmt.Errorf("migrate: list applied versions of %q", m.name), err)
		}
		for _, f := range m.files {
			if slices.Contains(applied, f) {
				continue
			}
			if err := apply(ctx, db, m, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// Check returns ErrNotMigrated, naming the first missing version, unless every migration embedded in
// fsys is recorded for module. It only reads, so a store's Ping can call it.
func Check(ctx context.Context, db Querier, module string, fsys fs.FS) error {
	files, err := listFiles(module, fsys)
	if err != nil {
		return err
	}
	var applied []string
	if err := db.QueryRow(ctx, selectApplied, module).Scan(&applied); err != nil {
		return errors.Join(fmt.Errorf("migrate: list applied versions of %q", module), err)
	}
	for _, f := range files {
		if !slices.Contains(applied, f) {
			return errors.Join(ErrNotMigrated, fmt.Errorf("module %q is missing version %q", module, f))
		}
	}
	return nil
}

type planned struct {
	name  string
	fsys  fs.FS
	files []string
}

func buildPlan(modules []Module) ([]planned, error) {
	var out []planned
	seen := map[string]bool{}
	for _, m := range modules {
		if !moduleName.MatchString(m.Name) {
			return nil, errors.Join(ErrInvalidModule, fmt.Errorf("module name %q", m.Name))
		}
		if seen[m.Name] {
			return nil, errors.Join(ErrInvalidModule, fmt.Errorf("module %q is listed twice", m.Name))
		}
		seen[m.Name] = true
		if m.FS == nil {
			continue
		}
		files, err := listFiles(m.Name, m.FS)
		if err != nil {
			return nil, err
		}
		out = append(out, planned{name: m.Name, fsys: m.FS, files: files})
	}
	return out, nil
}

func listFiles(module string, fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, migrationsDir)
	if err != nil {
		return nil, errors.Join(ErrInvalidModule, fmt.Errorf("module %q: read migrations", module), err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !fileVersion.MatchString(e.Name()) {
			return nil, errors.Join(ErrInvalidModule, fmt.Errorf("module %q: file name %q", module, e.Name()))
		}
		files = append(files, e.Name())
	}
	slices.Sort(files)
	return files, nil
}

func apply(ctx context.Context, db Querier, m planned, version string) error {
	body, err := fs.ReadFile(m.fsys, migrationsDir+"/"+version)
	if err != nil {
		return errors.Join(fmt.Errorf("migrate: read %q of %q", version, m.name), err)
	}
	record := "\nINSERT INTO egauth_schema_migrations (module, version) VALUES ('" +
		strings.ReplaceAll(m.name, "'", "''") + "', '" + strings.ReplaceAll(version, "'", "''") +
		"') ON CONFLICT (module, version) DO NOTHING;"
	if _, err := db.Exec(ctx, string(body)+record); err != nil {
		return errors.Join(fmt.Errorf("migrate: apply %q of %q", version, m.name), err)
	}
	return nil
}
