package pgx

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeIncrementRow is a minimal pgx.Row that reports a single int, matching the shape
// IncrementTOTPAttempts's single UPDATE ... RETURNING statement scans.
type fakeIncrementRow struct {
	attempts int
}

func (r fakeIncrementRow) Scan(dest ...any) error {
	*(dest[0].(*int)) = r.attempts
	return nil
}

// fakeIncrementDB is a DBQuerier that never touches a real database, recording how many
// round-trips (Exec + QueryRow calls combined) IncrementTOTPAttempts makes. It deliberately does
// NOT implement Begin/pgx.Tx, so the store cannot fall back to a transaction — this is exactly
// the bare-pool shape the atomicity bug depended on.
type fakeIncrementDB struct {
	roundTrips int
}

func (f *fakeIncrementDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	f.roundTrips++
	return pgconn.CommandTag{}, nil
}

func (f *fakeIncrementDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	f.roundTrips++
	return nil, nil
}

func (f *fakeIncrementDB) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	f.roundTrips++
	return fakeIncrementRow{attempts: 1}
}

// TestIncrementTOTPAttempts_IsSingleRoundTrip pins the atomicity fix structurally: a fake DB that
// cannot open a transaction (no Begin method) proves IncrementTOTPAttempts makes exactly ONE
// database round-trip. Before the fix, the non-transactional fallback path issued a SELECT ...
// FOR UPDATE and then a separate UPDATE — two round-trips — and the FOR UPDATE lock is released
// between them on a bare (autocommit) connection, so two concurrent callers could both read the
// same pre-increment count and lose an increment.
func TestIncrementTOTPAttempts_IsSingleRoundTrip(t *testing.T) {
	fdb := &fakeIncrementDB{}
	store := &Store{db: fdb}

	_, err := store.IncrementTOTPAttempts(context.Background(), "t1", uuid.Must(uuid.NewV7()), time.Now(), 5, time.Minute)
	if err != nil {
		t.Fatalf("IncrementTOTPAttempts: %v", err)
	}

	if fdb.roundTrips != 1 {
		t.Fatalf("IncrementTOTPAttempts must be a single atomic database statement, got %d round-trips", fdb.roundTrips)
	}
}
