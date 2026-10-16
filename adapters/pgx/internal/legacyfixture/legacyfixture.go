// Package legacyfixture reproduces the v0.16 pgx schemas for upgrade tests: the frozen migration
// files and the bookkeeping table that the removed per-module runners wrote. It exists only so the
// bootstrap and upgrade paths can be tested against a database a v0.16 deployment would have left.
package legacyfixture

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed testdata
var files embed.FS

// Module names one v0.16 migration set.
type Module string

// The v0.16 modules that upgrade tests need.
const (
	Identity Module = "identity"
	OTP      Module = "otp"
	Sessions Module = "sessions"
)

// ErrUnknownModule is returned by FS for a Module that has no frozen migration set.
var ErrUnknownModule = errors.New("legacyfixture: unknown module")

// FS returns the frozen migrations of m, rooted so that files sit under "migrations/". It returns
// ErrUnknownModule for a Module that is not one of the constants.
func FS(m Module) (fs.FS, error) {
	switch m {
	case Identity, OTP, Sessions:
		return fs.Sub(files, "testdata/"+string(m))
	}
	return nil, ErrUnknownModule
}

// Execer is satisfied by *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Migrate applies m exactly as v0.16 did: file by file, each recorded in schema_migrations by the
// same statement.
func Migrate(ctx context.Context, db Execer, m Module) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`); err != nil {
		return errors.Join(errors.New("legacyfixture: create schema_migrations"), err)
	}
	fsys, err := FS(m)
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return errors.Join(errors.New("legacyfixture: read migrations"), err)
	}
	for _, e := range entries {
		body, err := fs.ReadFile(fsys, "migrations/"+e.Name())
		if err != nil {
			return errors.Join(errors.New("legacyfixture: read "+e.Name()), err)
		}
		stmt := string(body) + "\nINSERT INTO schema_migrations (version) VALUES ('" +
			strings.ReplaceAll(e.Name(), "'", "''") + "') ON CONFLICT (version) DO NOTHING;"
		if _, err := db.Exec(ctx, stmt); err != nil {
			return errors.Join(errors.New("legacyfixture: apply "+e.Name()), err)
		}
	}
	return nil
}

// Account is a v0.16 user with a password identity.
type Account struct {
	Tenant string
	Email  string
	PHC    string
}

// CreatePasswordAccount inserts a into a database migrated with Migrate(Identity) and returns the
// user ID.
func CreatePasswordAccount(ctx context.Context, db Execer, a Account) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		id, a.Tenant, a.Email, now); err != nil {
		return uuid.Nil, err
	}
	identityID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO identities (id, user_id, tenant_id, provider, provider_id, password_hash, created_at, updated_at)
		 VALUES ($1, $2, $3, 'password', $4, $5, $6, $6)`,
		identityID, id, a.Tenant, a.Email, a.PHC, now); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}
