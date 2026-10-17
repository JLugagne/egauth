package pgxstore

import (
	"context"
	"errors"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	ceremonystore "github.com/JLugagne/egauth/adapters/pgx/store/ceremony"
	deploymentstore "github.com/JLugagne/egauth/adapters/pgx/store/deployment"
	federationstore "github.com/JLugagne/egauth/adapters/pgx/store/federation"
	identitystore "github.com/JLugagne/egauth/adapters/pgx/store/identity"
	keysstore "github.com/JLugagne/egauth/adapters/pgx/store/keys"
	limiterstore "github.com/JLugagne/egauth/adapters/pgx/store/limiter"
	mfastore "github.com/JLugagne/egauth/adapters/pgx/store/mfa"
	passkeystore "github.com/JLugagne/egauth/adapters/pgx/store/passkey"
	sessionsstore "github.com/JLugagne/egauth/adapters/pgx/store/sessions"
	tokensstore "github.com/JLugagne/egauth/adapters/pgx/store/tokens"
)

// DB is the handle New needs; *pgxpool.Pool satisfies it. It must stay usable for the life of the
// returned Storage.
type DB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// New returns a Storage with every field set, each store backed by db and Shared. It only reads:
// it fails when an embedded migration is not recorded, including on a database Migrate never ran
// on, naming the first missing module and version in registration order, so run Migrate first. It does not check connectivity beyond that read.
func New(ctx context.Context, db DB) (egauth.Storage, error) {
	if isNil(db) {
		return egauth.Storage{}, errors.New("pgxstore: nil db")
	}
	if err := verify(ctx, db); err != nil {
		return egauth.Storage{}, err
	}
	return egauth.Storage{
		Identity:   identitystore.New(db),
		Ceremonies: ceremonystore.New(db),
		Deployment: deploymentstore.New(db),
		Limiter:    limiterstore.New(db),
		Tokens:     tokensstore.New(db),
		Sessions:   sessionsstore.New(db),
		MFA:        mfastore.New(db),
		Passkeys:   passkeystore.New(db),
		Federation: federationstore.New(db),
		Keys:       keysstore.New(db),
	}, nil
}

func verify(ctx context.Context, db migrate.Querier) error {
	for _, m := range modules() {
		if m.FS == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err := migrate.Check(ctx, db, m.Name, m.FS)
		if undefinedTable(err) {
			err = errors.Join(migrate.Check(ctx, unmigrated{}, m.Name, m.FS), err)
		}
		if err != nil {
			return errors.Join(errors.New("pgxstore: schema is not ready"), err)
		}
	}
	return nil
}

func undefinedTable(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "42P01"
}

type unmigrated struct{}

func (unmigrated) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("pgxstore: no bookkeeping table")
}

func (unmigrated) QueryRow(context.Context, string, ...any) pgx.Row { return noVersions{} }

type noVersions struct{}

func (noVersions) Scan(dest ...any) error {
	for _, d := range dest {
		if v, ok := d.(*[]string); ok {
			*v = nil
		}
	}
	return nil
}

func isNil(db DB) bool {
	if db == nil {
		return true
	}
	v := reflect.ValueOf(db)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}
