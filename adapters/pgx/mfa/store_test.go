package pgx_test

import (
	"context"
	"encoding/base64"
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

// TestPgxStore_ConfirmEnrollmentAtomic verifies that ConfirmEnrollment executes within a single
// database transaction: if inserting recovery codes fails (e.g. duplicate hash trips PK),
// the entire transaction rolls back and the TOTP enrollment is NOT left confirmed (SEC-MFA-06).
func TestPgxStore_ConfirmEnrollmentAtomic(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	uid := uuid.Must(uuid.NewV7())

	enr := &mfa.TOTPEnrollment{
		UserID:   uid,
		TenantID: "t1",
		Secret:   "secret-key",
	}
	require.NoError(t, store.SaveTOTP(ctx, "t1", enr))

	// Attempt confirmation with duplicate recovery code hashes to cause PK violation during insert
	now := time.Now()
	enr.ConfirmedAt = &now
	enr.LastUsedStep = 42
	err := store.ConfirmEnrollment(ctx, "t1", enr, []string{"dup", "dup"})
	require.Error(t, err)

	// Because of transaction rollback, the TOTP enrollment must remain unconfirmed
	got, err := store.GetTOTP(ctx, "t1", uid)
	require.NoError(t, err)
	assert.False(t, got.Confirmed(), "TOTP factor must remain unconfirmed when recovery code persistence fails")
	assert.Nil(t, got.ConfirmedAt)
	assert.Equal(t, int64(0), got.LastUsedStep)

	// Zero recovery codes should exist for this user
	assert.ErrorIs(t, store.ConsumeRecoveryCode(ctx, "t1", uid, "dup"), mfa.ErrRecoveryCodeNotFound)

	// When called with unique codes, ConfirmEnrollment succeeds
	err = store.ConfirmEnrollment(ctx, "t1", enr, []string{"code1", "code2"})
	require.NoError(t, err)

	got, err = store.GetTOTP(ctx, "t1", uid)
	require.NoError(t, err)
	assert.True(t, got.Confirmed())
	assert.Equal(t, int64(42), got.LastUsedStep)
	assert.NoError(t, store.ConsumeRecoveryCode(ctx, "t1", uid, "code1"))
}

// TestPgxStore_SEC_MFA_03_CrossTenantAAD verifies that TOTP secrets are cryptographically bound
// to their tenant (and user) via AAD. An attacker copying a sealed ciphertext from tenant A to
// tenant B cannot read/decrypt it under tenant B (SEC-MFA-03).
func TestPgxStore_SEC_MFA_03_CrossTenantAAD(t *testing.T) {
	ctx := context.Background()
	store, pool := newStoreAndPool(t)
	uid := uuid.Must(uuid.NewV7())

	const secret = "super-secret-totp"
	enr := &mfa.TOTPEnrollment{
		UserID:   uid,
		TenantID: "tenant-a",
		Secret:   secret,
	}
	require.NoError(t, store.SaveTOTP(ctx, "tenant-a", enr))

	// Retrieve the raw ciphertext sealed for tenant-a
	var rawCiphertext string
	err := pool.QueryRow(ctx, "SELECT secret FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2", "tenant-a", uid).Scan(&rawCiphertext)
	require.NoError(t, err)

	// Simulate transposition of tenant-a's ciphertext into tenant-b's record
	_, err = pool.Exec(ctx, `
		INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at)
		VALUES ($1, $2, $3, NULL, 0, 0, NULL, $4)
	`, "tenant-b", uid, rawCiphertext, time.Now().UTC())
	require.NoError(t, err)

	// Attempting to read under tenant-b must fail due to AAD mismatch
	_, err = store.GetTOTP(ctx, "tenant-b", uid)
	require.Error(t, err, "reading transposed secret under tenant-b must fail due to AAD mismatch")
}

// TestPgxStore_SEC_MFA_03_BackwardCompatibility_LegacySecretWithoutAAD verifies that secrets sealed
// without AAD (pre-migration / legacy) can still be decrypted via fallback (SEC-MFA-03).
func TestPgxStore_SEC_MFA_03_BackwardCompatibility_LegacySecretWithoutAAD(t *testing.T) {
	ctx := context.Background()
	store, pool := newStoreAndPool(t)
	uid := uuid.Must(uuid.NewV7())

	dummyKey := make([]byte, 32)
	kek, err := keystore.NewKEK(dummyKey)
	require.NoError(t, err)

	const legacySecret = "legacy-unauthenticated-secret"
	// Seal without AAD (legacy behavior)
	sealed, err := kek.Seal([]byte(legacySecret))
	require.NoError(t, err)
	secretStr := base64.StdEncoding.EncodeToString(sealed)

	_, err = pool.Exec(ctx, `
		INSERT INTO mfa_totp (tenant_id, user_id, secret, confirmed_at, last_used_step, failed_attempts, last_attempt_at, created_at)
		VALUES ($1, $2, $3, NULL, 0, 0, NULL, $4)
	`, "tenant-legacy", uid, secretStr, time.Now().UTC())
	require.NoError(t, err)

	got, err := store.GetTOTP(ctx, "tenant-legacy", uid)
	require.NoError(t, err, "legacy secret without AAD must be opened successfully via fallback")
	assert.Equal(t, legacySecret, got.Secret)
}
