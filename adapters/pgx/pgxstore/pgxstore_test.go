package pgxstore_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/store"
)

type queryless struct{ *recorder }

func (queryless) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func migrated(t *testing.T) queryless {
	t.Helper()
	r := &recorder{applied: map[string][]string{}}
	require.NoError(t, pgxstore.Migrate(context.Background(), r))
	return queryless{r}
}

func TestNewFillsEveryStorageFieldOnAMigratedSchema(t *testing.T) {
	s, err := pgxstore.New(context.Background(), migrated(t))
	require.NoError(t, err)
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		require.False(t, v.Field(i).IsNil(), "Storage.%s is nil", name)
		b, ok := v.Field(i).Interface().(store.Base)
		require.True(t, ok, "Storage.%s", name)
		require.Equal(t, store.Shared, b.Durability(), "Storage.%s", name)
	}
}

func TestNewNamesTheFirstMissingModuleAndVersion(t *testing.T) {
	db := migrated(t)
	federation := db.applied["federation"]
	require.NotEmpty(t, federation)
	db.applied["federation"] = federation[:len(federation)-1]
	_, err := pgxstore.New(context.Background(), db)
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "federation" is missing version "`+federation[len(federation)-1]+`"`)

	identity := db.applied["identity"]
	require.NotEmpty(t, identity)
	db.applied["identity"] = identity[1:]
	_, err = pgxstore.New(context.Background(), db)
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "identity" is missing version "`+identity[0]+`"`)
	require.False(t, strings.Contains(err.Error(), "federation"), "only the first missing module is named: %v", err)
}

func TestNewRefusesAnUnmigratedSchema(t *testing.T) {
	db := queryless{&recorder{applied: map[string][]string{}}}
	_, err := pgxstore.New(context.Background(), db)
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "ceremony"`)
}

func TestNewHonoursACancelledContextAndNilDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pgxstore.New(ctx, migrated(t))
	require.ErrorIs(t, err, context.Canceled)
	_, err = pgxstore.New(context.Background(), nil)
	require.Error(t, err)
}

type freshDB struct{ queryless }

type undefinedTableRow struct{}

func (undefinedTableRow) Scan(...any) error {
	return &pgconn.PgError{Code: "42P01", Message: `relation "egauth_schema_migrations" does not exist`}
}

func (freshDB) QueryRow(context.Context, string, ...any) pgx.Row { return undefinedTableRow{} }

func TestNewOnADatabaseNeverMigratedNamesTheFirstModuleAndVersion(t *testing.T) {
	want := migrated(t).applied["ceremony"]
	require.NotEmpty(t, want)
	_, err := pgxstore.New(context.Background(), freshDB{queryless{&recorder{}}})
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "ceremony" is missing version "`+want[0]+`"`)
}

func TestNewRefusesATypedNilDB(t *testing.T) {
	var pool *pgxpool.Pool
	require.NotPanics(t, func() {
		_, err := pgxstore.New(context.Background(), pool)
		require.Error(t, err)
	})
}

func TestNewAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	_, err := pgxstore.New(ctx, pool)
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "ceremony" is missing version "`)

	require.NoError(t, pgxstore.Migrate(ctx, pool))
	s, err := pgxstore.New(ctx, pool)
	require.NoError(t, err)
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		b := v.Field(i).Interface().(store.Base)
		require.NoError(t, b.Ping(ctx), "Storage.%s", v.Type().Field(i).Name)
		require.Equal(t, store.Shared, b.Durability(), "Storage.%s", v.Type().Field(i).Name)
	}

	_, err = pool.Exec(ctx, `DELETE FROM egauth_schema_migrations WHERE module = 'keys'`)
	require.NoError(t, err)
	_, err = pgxstore.New(ctx, pool)
	require.ErrorIs(t, err, migrate.ErrNotMigrated)
	require.Contains(t, err.Error(), `module "keys" is missing version "`)
}
