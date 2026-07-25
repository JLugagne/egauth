package pgxmigrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRow is a minimal pgx.Row so tests can drive QueryRow without a real connection.
type fakeRow struct {
	scan func(dest ...any) error
}

func (r fakeRow) Scan(dest ...any) error { return r.scan(dest...) }

// fakeQuerier is a Querier that never touches a real database, recording every Exec call so
// tests can assert on the lock/unlock sequence, and optionally failing an Exec whose SQL
// contains failExecContains so tests can simulate a migration failing mid-run.
type fakeQuerier struct {
	execCalls        []string
	failExecContains string
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.execCalls = append(f.execCalls, sql)
	if f.failExecContains != "" && strings.Contains(sql, f.failExecContains) {
		return pgconn.CommandTag{}, errors.New("boom")
	}
	return pgconn.CommandTag{}, nil
}

func (f *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return fakeRow{scan: func(dest ...any) error {
		*(dest[0].(*bool)) = false // nothing recorded as applied yet
		return nil
	}}
}

// TestLockKeyForNamespace pins the two properties concurrent callers rely on: the key is
// deterministic (repeat calls with the same namespace must contend on the same lock) and it
// distinguishes different namespaces (different modules must never serialise against each other).
func TestLockKeyForNamespace(t *testing.T) {
	a1 := lockKeyForNamespace("identity")
	a2 := lockKeyForNamespace("identity")
	b := lockKeyForNamespace("tokens")

	if a1 != a2 {
		t.Fatalf("lockKeyForNamespace must be deterministic: got %d and %d for the same namespace", a1, a2)
	}
	if a1 == b {
		t.Fatalf("lockKeyForNamespace must differ across namespaces: identity and tokens both got %d", a1)
	}
}

// TestRun_AcquiresAndReleasesAdvisoryLock proves the happy path takes the advisory lock before
// touching the schema and releases it as the very last statement.
func TestRun_AcquiresAndReleasesAdvisoryLock(t *testing.T) {
	fsys := fstest.MapFS{"migrations/001_x.sql": {Data: []byte("SELECT 1;")}}
	fq := &fakeQuerier{}

	if err := Run(context.Background(), fq, fsys, "test-ns"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(fq.execCalls) == 0 || fq.execCalls[0] != "SELECT pg_advisory_lock($1)" {
		t.Fatalf("advisory lock must be acquired before any other statement; exec calls: %v", fq.execCalls)
	}
	last := fq.execCalls[len(fq.execCalls)-1]
	if last != "SELECT pg_advisory_unlock($1)" {
		t.Fatalf("advisory lock must be released as the last statement; exec calls: %v", fq.execCalls)
	}
}

// TestRun_ReleasesAdvisoryLockOnError proves the lock is released even when a migration fails
// partway through the run, so a crashed/erroring migrator never leaves the namespace wedged for
// every other replica trying to start.
func TestRun_ReleasesAdvisoryLockOnError(t *testing.T) {
	fsys := fstest.MapFS{"migrations/001_x.sql": {Data: []byte("SELECT 1;")}}
	fq := &fakeQuerier{failExecContains: "SELECT 1;"}

	err := Run(context.Background(), fq, fsys, "test-ns")
	if err == nil {
		t.Fatal("expected Run to report the failing migration's error")
	}

	last := fq.execCalls[len(fq.execCalls)-1]
	if last != "SELECT pg_advisory_unlock($1)" {
		t.Fatalf("advisory lock must be released on the error path too; exec calls: %v", fq.execCalls)
	}
}
