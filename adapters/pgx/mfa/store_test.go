package pgx_test

import (
	"context"
	"testing"
	"time"

	mfapgx "github.com/JLugagne/egauth/adapters/pgx/mfa"
	"github.com/JLugagne/egauth/mfa/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newStore(t *testing.T) *mfapgx.Store {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(15*time.Second),
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

	require.NoError(t, mfapgx.Migrate(ctx, pool))
	return mfapgx.NewStore(pool)
}

func TestPgxStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, newStore(t), true)
}

// TestPgxStore_ReplaceRecoveryCodesAtomic verifies the documented atomicity: a replace that
// fails partway (here, a duplicate hash trips the primary key on the second INSERT) must NOT
// destroy the user's existing recovery codes.
func TestPgxStore_ReplaceRecoveryCodesAtomic(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	uid := uuid.New()

	require.NoError(t, store.ReplaceRecoveryCodes(ctx, "t1", uid, []string{"keepA", "keepB"}))

	// A duplicate hash makes the second INSERT violate the PK, failing the replace mid-loop.
	err := store.ReplaceRecoveryCodes(ctx, "t1", uid, []string{"dup", "dup"})
	require.Error(t, err)

	// Because the replace is transactional, the original codes must still be intact.
	assert.NoError(t, store.ConsumeRecoveryCode(ctx, "t1", uid, "keepA"),
		"a failed replace must roll back, leaving the previous recovery codes usable")
	assert.NoError(t, store.ConsumeRecoveryCode(ctx, "t1", uid, "keepB"))
}
