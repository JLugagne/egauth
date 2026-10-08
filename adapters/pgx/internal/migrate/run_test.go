package migrate_test

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JLugagne/egauth/adapters/pgx/internal/migrate"
)

type fakeDB struct {
	legacyShape    []string
	legacyVersions []string
	recorded       map[string][]string
	executed       []string
	writesLegacy   bool
	locked         int
	commits        int
	rollbacks      int
	failOn         string
}

type fakeTx struct {
	pgx.Tx
	f *fakeDB
}

func (tx fakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.f.Exec(ctx, sql, args...)
}

func (tx fakeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return tx.f.QueryRow(ctx, sql, args...)
}

func (tx fakeTx) Commit(context.Context) error {
	tx.f.commits++
	return nil
}

func (tx fakeTx) Rollback(context.Context) error {
	tx.f.rollbacks++
	return nil
}

func (f *fakeDB) Begin(context.Context) (pgx.Tx, error) { return fakeTx{f: f}, nil }

var recordRE = regexp.MustCompile(`INSERT INTO egauth_schema_migrations \(module, version\) VALUES \('([^']*)', '([^']*)'\)`)

func newFake() *fakeDB { return &fakeDB{recorded: map[string][]string{}} }

func (f *fakeDB) record(module, version string) {
	if !slices.Contains(f.recorded[module], version) {
		f.recorded[module] = append(f.recorded[module], version)
	}
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		f.locked++
	case strings.HasPrefix(sql, "CREATE TABLE IF NOT EXISTS egauth_schema_migrations"):
	case strings.HasPrefix(sql, "INSERT INTO egauth_schema_migrations") && len(args) == 2:
		f.record(args[0].(string), args[1].(string))
	default:
		if strings.Contains(sql, "INSERT INTO schema_migrations") || strings.Contains(sql, "DROP TABLE schema_migrations") {
			f.writesLegacy = true
		}
		if f.failOn != "" && strings.Contains(sql, f.failOn) {
			return pgconn.CommandTag{}, errors.New("boom")
		}
		f.executed = append(f.executed, sql)
		if m := recordRE.FindStringSubmatch(sql); m != nil {
			f.record(m[1], m[2])
		}
	}
	return pgconn.CommandTag{}, nil
}

type fakeRow struct{ vals [][]string }

func (r fakeRow) Scan(dest ...any) error {
	for i, d := range dest {
		*(d.(*[]string)) = r.vals[i]
	}
	return nil
}

func (f *fakeDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "information_schema.columns"):
		return fakeRow{[][]string{f.legacyShape}}
	case strings.Contains(sql, "FROM schema_migrations"):
		return fakeRow{[][]string{f.legacyVersions}}
	case strings.Contains(sql, "FROM egauth_schema_migrations"):
		return fakeRow{[][]string{f.recorded[args[0].(string)]}}
	}
	panic("unexpected query: " + sql)
}

func files(names ...string) fstest.MapFS {
	m := fstest.MapFS{}
	for _, n := range names {
		m["migrations/"+n] = &fstest.MapFile{Data: []byte("-- " + n)}
	}
	return m
}

func countContaining(f *fakeDB, marker string) int {
	n := 0
	for _, s := range f.executed {
		if strings.Contains(s, marker) {
			n++
		}
	}
	return n
}

func TestRunAppliesInOrderRecordsAndIsIdempotent(t *testing.T) {
	db := newFake()
	mods := []migrate.Module{{Name: "a", FS: files("002_b.sql", "001_a.sql")}, {Name: "stub"}}
	if err := migrate.Run(context.Background(), db, mods); err != nil {
		t.Fatal(err)
	}
	if len(db.executed) != 2 || !strings.HasPrefix(db.executed[0], "-- 001_a.sql") || !strings.HasPrefix(db.executed[1], "-- 002_b.sql") {
		t.Fatalf("executed %q", db.executed)
	}
	if !slices.Equal(db.recorded["a"], []string{"001_a.sql", "002_b.sql"}) {
		t.Fatalf("recorded %v", db.recorded)
	}
	if err := migrate.Run(context.Background(), db, mods); err != nil {
		t.Fatal(err)
	}
	if len(db.executed) != 2 {
		t.Fatalf("second run re-executed files: %q", db.executed)
	}
}

func TestRunRejectsBadModuleLists(t *testing.T) {
	for name, mods := range map[string][]migrate.Module{
		"empty name": {{Name: ""}},
		"quote":      {{Name: "a'b"}},
		"duplicate":  {{Name: "a"}, {Name: "a"}},
		"bad file":   {{Name: "a", FS: files("x';drop.sql")}},
		"no dir":     {{Name: "a", FS: fstest.MapFS{"other/x.sql": {}}}},
	} {
		err := migrate.Run(context.Background(), newFake(), mods)
		if !errors.Is(err, migrate.ErrInvalidModule) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

var v016Shape = []string{"applied_at timestamp with time zone", "version text"}

func TestRunHoldsOneLockedTransaction(t *testing.T) {
	db := newFake()
	if err := migrate.Run(context.Background(), db, []migrate.Module{{Name: "a", FS: files("001_a.sql")}}); err != nil {
		t.Fatal(err)
	}
	if db.locked != 1 || db.commits != 1 || db.rollbacks != 0 {
		t.Fatalf("locked %d, committed %d, rolled back %d", db.locked, db.commits, db.rollbacks)
	}
	db = newFake()
	db.failOn = "-- 002_b.sql"
	err := migrate.Run(context.Background(), db, []migrate.Module{{Name: "a", FS: files("001_a.sql", "002_b.sql")}})
	if err == nil || db.commits != 0 || db.rollbacks != 1 {
		t.Fatalf("err %v, committed %d, rolled back %d", err, db.commits, db.rollbacks)
	}
}

func TestBootstrapCopiesTheRealV016Table(t *testing.T) {
	db := newFake()
	db.legacyShape = v016Shape
	db.legacyVersions = []string{"001_create_tables.sql", "002_add_account_lockout.sql", "001_create_sessions_table.sql"}
	mods := []migrate.Module{
		{Name: "identity", FS: files("001_create_tables.sql", "002_add_account_lockout.sql", "009_security_epoch.sql")},
	}
	if err := migrate.Run(context.Background(), db, mods); err != nil {
		t.Fatal(err)
	}
	if countContaining(db, "-- 001_create_tables.sql") != 0 || countContaining(db, "-- 002_add_account_lockout.sql") != 0 {
		t.Fatalf("v0.16 files were re-run: %q", db.executed)
	}
	if countContaining(db, "-- 009_security_epoch.sql") != 1 {
		t.Fatal("the v0.17 file did not run")
	}
	if slices.Contains(db.recorded["identity"], "001_create_sessions_table.sql") || db.writesLegacy {
		t.Fatal("foreign or legacy state was touched")
	}
}

func TestBootstrapRerunsCollidingBasenameEvenWhenItsOtherOwnerIsUnregistered(t *testing.T) {
	db := newFake()
	db.legacyShape = v016Shape
	db.legacyVersions = []string{"001_create_otp_codes.sql", "002_add_expires_at_index.sql"}
	mods := []migrate.Module{{Name: "sessions", FS: files("001_create_sessions_table.sql", "002_add_expires_at_index.sql")}}
	if err := migrate.Run(context.Background(), db, mods); err != nil {
		t.Fatal(err)
	}
	if countContaining(db, "-- 002_add_expires_at_index.sql") != 1 || countContaining(db, "-- 001_create_sessions_table.sql") != 1 {
		t.Fatalf("executed %q", db.executed)
	}
}

func TestBootstrapNeverCopiesABasenameIntoAnotherModule(t *testing.T) {
	db := newFake()
	db.legacyShape = v016Shape
	db.legacyVersions = []string{"001_create_tables.sql", "001_init.sql"}
	mods := []migrate.Module{
		{Name: "sessions", FS: files("001_create_tables.sql")},
		{Name: "ceremony", FS: files("001_init.sql")},
	}
	if err := migrate.Run(context.Background(), db, mods); err != nil {
		t.Fatal(err)
	}
	if len(db.executed) != 2 {
		t.Fatalf("a row v0.16 wrote for another module was copied: executed %q", db.executed)
	}
}

func TestBootstrapIgnoresOtherShapes(t *testing.T) {
	shapes := map[string][]string{
		"golang-migrate": {"dirty boolean", "version bigint"},
		"bigint version": {"applied_at timestamp with time zone", "version bigint"},
		"version only":   {"version text"},
		"extra column":   {"applied_at timestamp with time zone", "dirty boolean", "version text"},
		"naive applied":  {"applied_at timestamp without time zone", "version text"},
		"absent":         nil,
	}
	for name, s := range shapes {
		db := newFake()
		db.legacyShape = s
		db.legacyVersions = []string{"001_create_tables.sql"}
		if err := migrate.Run(context.Background(), db, []migrate.Module{{Name: "identity", FS: files("001_create_tables.sql")}}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if countContaining(db, "-- 001_create_tables.sql") != 1 || db.writesLegacy {
			t.Errorf("%s: shape was not ignored (executed %q)", name, db.executed)
		}
	}
}

func TestCheckNamesFirstMissingVersion(t *testing.T) {
	db := newFake()
	fsys := files("001_a.sql", "002_b.sql")
	db.recorded["m"] = []string{"001_a.sql"}
	err := migrate.Check(context.Background(), db, "m", fsys)
	if !errors.Is(err, migrate.ErrNotMigrated) || !strings.Contains(err.Error(), `"002_b.sql"`) {
		t.Fatalf("err = %v", err)
	}
	db.recorded["m"] = append(db.recorded["m"], "002_b.sql")
	if err := migrate.Check(context.Background(), db, "m", fsys); err != nil {
		t.Fatal(err)
	}
}
