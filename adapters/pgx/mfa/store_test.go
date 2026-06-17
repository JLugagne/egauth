package pgx_test

import (
	"context"
	"testing"
	"time"

	mfapgx "github.com/JLugagne/egauth/adapters/pgx/mfa"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newStoreAndPool(t *testing.T) (*mfapgx.Store, *pgxpool.Pool) {
	t.Helper()
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

	// Provide a dummy KEK for testing
	dummyKey := make([]byte, 32)
	kek, err := keystore.NewKEK(dummyKey)
	require.NoError(t, err)

	return mfapgx.NewStore(pool, kek), pool
}

func newStore(t *testing.T) *mfapgx.Store {
	store, _ := newStoreAndPool(t)
	return store
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
	uid := uuid.Must(uuid.NewV7())

	require.NoError(t, store.ReplaceRecoveryCodes(ctx, "t1", uid, []string{"keepA", "keepB"}))

	// A duplicate hash makes the second INSERT violate the PK, failing the replace mid-loop.
	err := store.ReplaceRecoveryCodes(ctx, "t1", uid, []string{"dup", "dup"})
	require.Error(t, err)

	// Because the replace is transactional, the original codes must still be intact.
	assert.NoError(t, store.ConsumeRecoveryCode(ctx, "t1", uid, "keepB"))
}

// TestPgxStore_TOTPSecretEncryptedAtRest verifies that the TOTP secret is not stored in plaintext.
func TestPgxStore_TOTPSecretEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	store, pool := newStoreAndPool(t)
	uid := uuid.Must(uuid.NewV7())

	const plaintextSecret = "my-super-secret-totp-key"

	// Save an enrollment
	enr := &mfa.TOTPEnrollment{
		UserID:   uid,
		TenantID: "t1",
		Secret:   plaintextSecret,
	}
	err := store.SaveTOTP(ctx, "t1", enr)
	require.NoError(t, err)

	// Read it back via the store to ensure it encrypts/decrypts correctly
	readEnr, err := store.GetTOTP(ctx, "t1", uid)
	require.NoError(t, err)
	assert.Equal(t, plaintextSecret, readEnr.Secret)

	// Now query the DB directly to ensure the raw column does NOT contain the plaintext secret
	var rawSecret []byte
	err = pool.QueryRow(ctx, "SELECT secret FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2", "t1", uid).Scan(&rawSecret)
	require.NoError(t, err)
	assert.NotEqual(t, plaintextSecret, string(rawSecret), "TOTP secret must be encrypted at rest, not stored in plaintext")
}
