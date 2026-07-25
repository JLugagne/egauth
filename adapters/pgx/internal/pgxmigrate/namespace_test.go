package pgxmigrate_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/JLugagne/egauth/adapters/pgx/internal/pgxmigrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var versionInsertRE = regexp.MustCompile(`INSERT INTO schema_migrations \(version\) VALUES \('((?:[^']|'')*)'\)`)

type recordingDB struct {
	recorded map[string]bool
	checked  []string
	bodies   []string
}

func newRecordingDB() *recordingDB {
	return &recordingDB{recorded: make(map[string]bool)}
}

func (d *recordingDB) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	m := versionInsertRE.FindStringSubmatch(sql)
	if m == nil {
		return pgconn.CommandTag{}, nil
	}
	d.recorded[strings.ReplaceAll(m[1], "''", "'")] = true
	d.bodies = append(d.bodies, sql[:strings.LastIndex(sql, "INSERT INTO schema_migrations")])
	return pgconn.CommandTag{}, nil
}

func (d *recordingDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	version, _ := args[0].(string)
	d.checked = append(d.checked, version)
	return boolRow{value: d.recorded[version]}
}

type boolRow struct{ value bool }

func (r boolRow) Scan(dest ...any) error {
	if p, ok := dest[0].(*bool); ok {
		*p = r.value
	}
	return nil
}

func migrationFS(name, body string) fstest.MapFS {
	return fstest.MapFS{"migrations/" + name: &fstest.MapFile{Data: []byte(body)}}
}

func TestRunAppliesSameFilenameInDifferentNamespaces(t *testing.T) {
	const shared = "002_add_expires_at_index.sql"
	db := newRecordingDB()
	ctx := context.Background()

	sessions := migrationFS(shared, "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);")
	otp := migrationFS(shared, "CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes (expires_at);")

	require.NoError(t, pgxmigrate.Run(ctx, db, sessions, "sessions"))
	require.NoError(t, pgxmigrate.Run(ctx, db, otp, "otp"))

	applied := strings.Join(db.bodies, "\n")
	assert.Contains(t, applied, "idx_sessions_expires_at",
		"the sessions migration must be applied")
	assert.Contains(t, applied, "idx_otp_codes_expires_at",
		"the otp migration must be applied even though sessions ships a file with the identical name")
}

func TestRunRecordsVersionsPrefixedByNamespace(t *testing.T) {
	db := newRecordingDB()
	ctx := context.Background()

	require.NoError(t, pgxmigrate.Run(ctx, db,
		migrationFS("001_create_tables.sql", "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY);"),
		"identity"))

	for version := range db.recorded {
		assert.True(t, strings.HasPrefix(version, "identity:"),
			"recorded version %q must be namespaced so two packages cannot collide", version)
	}
	assert.Contains(t, db.recorded, "identity:001_create_tables.sql")
}

func TestRunIsNoOpForAnAlreadyRecordedNamespacedVersion(t *testing.T) {
	db := newRecordingDB()
	ctx := context.Background()
	fsys := migrationFS("001_create_tables.sql", "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY);")

	require.NoError(t, pgxmigrate.Run(ctx, db, fsys, "identity"))
	first := len(db.bodies)
	require.NoError(t, pgxmigrate.Run(ctx, db, fsys, "identity"))

	assert.Equal(t, first, len(db.bodies), "re-running the same namespace must not re-apply the file")
}
