package pgx_test

import (
	"context"
	"testing"
	"time"

	otppgx "github.com/JLugagne/egauth/adapters/pgx/otp"
	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPgxStore_Contract(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate pgContainer: %s", err)
		}
	})

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, otppgx.Migrate(ctx, pool))

	storetest.StoreContractTesting(t, otppgx.NewStore(pool), true)
}

// TestPgxStore_IssueOTPCooldownSurvivesExpiry pins the issuance-tombstone contract the shared
// suite does not cover: purging an expired code (the OTPReaper sweep) must not reset the resend
// cooldown, a non-positive cooldown disables the check, and a contradictory tenant on the record
// is rejected before any write.
func TestPgxStore_IssueOTPCooldownSurvivesExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
	}
	ctx := context.Background()
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })
	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, otppgx.Migrate(ctx, pool))
	// Migrate is idempotent: re-running it must be a no-op (all files are guarded).
	require.NoError(t, otppgx.Migrate(ctx, pool))

	store := otppgx.NewStore(pool)
	sub := uuid.Must(uuid.NewV7())
	base := time.Now()

	// First issue: the code is already expired, so the reaper sweep purges it right away.
	require.NoError(t, store.IssueOTP(ctx, "t1", &otp.OTP{
		SubjectID: sub, Purpose: "login", CodeHash: "h1",
		ExpiresAt: base.Add(-time.Minute), CreatedAt: base,
	}, time.Minute))

	n, err := store.DeleteExpired(ctx, "t1")
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1))

	// The tombstone survives the sweep: still inside the cooldown.
	require.ErrorIs(t, store.IssueOTP(ctx, "t1", &otp.OTP{
		SubjectID: sub, Purpose: "login", CodeHash: "h2",
		ExpiresAt: base.Add(time.Minute), CreatedAt: base.Add(10 * time.Second),
	}, time.Minute), otp.ErrCooldownActive)

	// A non-positive cooldown disables the check...
	require.NoError(t, store.IssueOTP(ctx, "t1", &otp.OTP{
		SubjectID: sub, Purpose: "login", CodeHash: "h3",
		ExpiresAt: base.Add(time.Minute), CreatedAt: base.Add(20 * time.Second),
	}, 0))

	// ...and a contradictory tenant on the record is rejected before any write.
	require.ErrorIs(t, store.IssueOTP(ctx, "t1", &otp.OTP{
		SubjectID: sub, Purpose: "login", CodeHash: "h4", TenantID: "other",
		ExpiresAt: base.Add(time.Minute), CreatedAt: base.Add(30 * time.Second),
	}, 0), otp.ErrTenantMismatch)
}
