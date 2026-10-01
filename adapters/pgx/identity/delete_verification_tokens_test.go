// Regression coverage for the identity verification-token eraser added for account erasure:
// DeleteVerificationTokensByUser must purge every pending token of one user in one tenant,
// leave another user's (and another tenant's) tokens alone, and be safe to retry.

package pgx_test

import (
	"context"
	"testing"
	"time"

	identitypgx "github.com/JLugagne/egauth/adapters/pgx/identity"
	"github.com/JLugagne/egauth/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestPgxStore_DeleteVerificationTokensByUser covers the tenant-scoped bulk delete, including
// the idempotent retry and the isolation from another user and another tenant.
func TestPgxStore_DeleteVerificationTokensByUser(t *testing.T) {
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
	require.NoError(t, identitypgx.Migrate(ctx, pool))

	store := identitypgx.NewStore(pool)

	user, err := store.CreateUser(ctx, "tenant-a", "erase-me@example.com")
	require.NoError(t, err)
	other, err := store.CreateUser(ctx, "tenant-a", "keep-me@example.com")
	require.NoError(t, err)
	otherTenant, err := store.CreateUser(ctx, "tenant-b", "other-tenant@example.com")
	require.NoError(t, err)

	firstToken, err := store.CreateVerificationToken(ctx, "tenant-a", user.ID, "email_verify", time.Hour, nil)
	require.NoError(t, err)
	_, err = store.CreateVerificationToken(ctx, "tenant-a", user.ID, "password_reset", time.Hour, []byte("meta"))
	require.NoError(t, err)
	otherToken, err := store.CreateVerificationToken(ctx, "tenant-a", other.ID, "email_verify", time.Hour, nil)
	require.NoError(t, err)
	otherTenantToken, err := store.CreateVerificationToken(ctx, "tenant-b", otherTenant.ID, "email_verify", time.Hour, nil)
	require.NoError(t, err)

	deleted, err := store.DeleteVerificationTokensByUser(ctx, "tenant-a", user.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted, "both of the user's tokens must be deleted")

	// The deleted tokens are gone.
	_, _, err = store.ConsumeVerificationToken(ctx, "tenant-a", firstToken, "email_verify")
	assert.ErrorIs(t, err, identity.ErrVerificationTokenNotFound)

	// Another user's token in the same tenant survives.
	uid, _, err := store.ConsumeVerificationToken(ctx, "tenant-a", otherToken, "email_verify")
	require.NoError(t, err)
	assert.Equal(t, other.ID, uid)

	// Another tenant's token survives too.
	uid, _, err = store.ConsumeVerificationToken(ctx, "tenant-b", otherTenantToken, "email_verify")
	require.NoError(t, err)
	assert.Equal(t, otherTenant.ID, uid)

	// Idempotent retry: nothing left to delete, no error.
	deleted, err = store.DeleteVerificationTokensByUser(ctx, "tenant-a", user.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}
