package internal_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	pgxstore "github.com/JLugagne/egauth/identity/pgx"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIdentityLifecycle_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// 1. Setup Postgres Testcontainer
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

	// 2. Connect with pgxpool
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
	})

	// 3. Run Migrations
	err = pgxstore.Migrate(ctx, pool)
	require.NoError(t, err)

	// 4. Instantiate Components
	store := pgxstore.NewStore(pool)
	hasher := argon2.NewHasher()
	pol := policy.NewDefaultPolicy()
	service := identity.NewService(store, hasher, pol)
	// Test Variables
	tenantA := "tenant-A"
	tenantB := "tenant-B"
	email := "test@tenant.com"
	password := "ValidPassword123!"

	t.Run("End-to-End Success", func(t *testing.T) {
		// Register in Tenant A
		user, err := service.Register(ctx, email, password, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, email, user.Email)

		// Authenticate with correct password in Tenant A
		authUser, err := service.Authenticate(ctx, "password", email, password, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.NotNil(t, authUser)
		assert.Equal(t, user.ID, authUser.ID)
	})

	t.Run("Tenant Isolation", func(t *testing.T) {
		// Attempt to authenticate with same email/password in Tenant B
		authUser, err := service.Authenticate(ctx, "password", email, password, identity.WithTenant(tenantB))
		require.Error(t, err)
		assert.Nil(t, authUser)
		assert.ErrorIs(t, err, identity.ErrInvalidCredentials)
	})

	t.Run("Soft Delete and Re-register", func(t *testing.T) {
		// Authenticate to get the user ID
		authUser, err := service.Authenticate(ctx, "password", email, password, identity.WithTenant(tenantA))
		require.NoError(t, err)

		// Soft delete via store
		err = store.DeleteUser(ctx, authUser.ID, identity.WithTenant(tenantA))
		require.NoError(t, err)

		// Re-register with the EXACT same email and tenant
		newUser, err := service.Register(ctx, email, password, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.NotNil(t, newUser)
		assert.NotEqual(t, authUser.ID, newUser.ID)
		assert.Equal(t, email, newUser.Email)

		// Authenticate with the new user
		newAuthUser, err := service.Authenticate(ctx, "password", email, password, identity.WithTenant(tenantA))
		require.NoError(t, err)
		assert.NotNil(t, newAuthUser)
		assert.Equal(t, newUser.ID, newAuthUser.ID)
	})
}
