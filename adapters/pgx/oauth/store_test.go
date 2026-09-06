package pgx_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	oauthpgx "github.com/JLugagne/egauth/adapters/pgx/oauth"
	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/oauth"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type dummyKEK struct{}

func (dummyKEK) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (dummyKEK) Open(_ context.Context, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

type wrappedKEK struct {
	k *keystore.KEK
}

func (w wrappedKEK) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	return w.k.Seal(plaintext)
}

func (w wrappedKEK) Open(_ context.Context, ciphertext []byte) ([]byte, error) {
	return w.k.Open(ciphertext)
}

func (w wrappedKEK) SealWithAAD(_ context.Context, plaintext []byte, aad []byte) ([]byte, error) {
	return w.k.Seal(plaintext, aad)
}

func (w wrappedKEK) OpenWithAAD(_ context.Context, ciphertext []byte, aad []byte) ([]byte, error) {
	return w.k.Open(ciphertext, aad)
}

func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker (testcontainers); run without -short")
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
		_ = pgContainer.Terminate(ctx)
	})

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// 2. Connect with pgxpool
	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	require.NoError(t, oauthpgx.Migrate(ctx, pool))

	store := oauthpgx.NewStore(pool, dummyKEK{})
	const tenantID = "tenant-123"
	const providerName = "my-sso"

	config := oauthpgx.OIDCProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
		Scopes:       []string{"openid", "email", "profile"},
	}

	// 1. Not found initially
	_, err = store.GetProvider(ctx, tenantID, providerName)
	require.ErrorIs(t, err, oauth.ErrProviderNotFound)

	// 2. Upsert and verify
	require.NoError(t, store.UpsertProvider(ctx, tenantID, providerName, config))

	p, err := store.GetProvider(ctx, tenantID, providerName)
	require.NoError(t, err)
	require.Equal(t, providerName, p.Name())

	// 3. Upsert again to test update (ON CONFLICT DO UPDATE)
	config.ClientID = "new-client-id"
	require.NoError(t, store.UpsertProvider(ctx, tenantID, providerName, config))

	// 4. Delete
	require.NoError(t, store.DeleteProvider(ctx, tenantID, providerName))
	_, err = store.GetProvider(ctx, tenantID, providerName)
	require.ErrorIs(t, err, oauth.ErrProviderNotFound)
}

func TestPgxStore_OAuthSecretEncryptedAtRest(t *testing.T) {
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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, oauthpgx.Migrate(ctx, pool))

	// Provide a real KEK for testing
	dummyKey := make([]byte, 32)
	k, err := keystore.NewKEK(dummyKey)
	require.NoError(t, err)

	store := oauthpgx.NewStore(pool, wrappedKEK{k})
	const tenantID = "tenant-test"
	const providerName = "my-secure-sso"

	config := oauthpgx.OIDCProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "my-super-secret-client-secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
		Scopes:       []string{"openid", "email"},
	}

	require.NoError(t, store.UpsertProvider(ctx, tenantID, providerName, config))

	// Now query the DB directly to ensure the raw column does NOT contain the plaintext secret
	var rawSecret []byte
	err = pool.QueryRow(ctx, "SELECT client_secret FROM oauth_oidc_providers WHERE tenant_id = $1 AND provider_name = $2", tenantID, providerName).Scan(&rawSecret)
	require.NoError(t, err)
	require.NotEqual(t, config.ClientSecret, string(rawSecret), "OAuth client_secret must be encrypted at rest, not stored in plaintext")
}

// TestPgxStore_SEC_OAU_02_CrossTenantAAD verifies that client_secrets are cryptographically bound
// to their tenant and provider via AAD (SEC-OAU-02). An attacker transposing ciphertext from
// tenant A to tenant B cannot decrypt it under tenant B.
func TestPgxStore_SEC_OAU_02_CrossTenantAAD(t *testing.T) {
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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, oauthpgx.Migrate(ctx, pool))

	dummyKey := make([]byte, 32)
	k, err := keystore.NewKEK(dummyKey)
	require.NoError(t, err)

	store := oauthpgx.NewStore(pool, wrappedKEK{k})
	const tenantA = "tenant-a"
	const tenantB = "tenant-b"
	const providerName = "sso-test"

	config := oauthpgx.OIDCProviderConfig{
		ClientID:     "client-id-a",
		ClientSecret: "super-secret-client-token",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
		Scopes:       []string{"openid", "email"},
	}

	require.NoError(t, store.UpsertProvider(ctx, tenantA, providerName, config))

	// Retrieve the sealed ciphertext from tenant-a
	var rawCiphertext string
	err = pool.QueryRow(ctx, "SELECT client_secret FROM oauth_oidc_providers WHERE tenant_id = $1 AND provider_name = $2", tenantA, providerName).Scan(&rawCiphertext)
	require.NoError(t, err)

	// Simulate transposition of tenant-a's sealed ciphertext into tenant-b's record
	_, err = pool.Exec(ctx, `
		INSERT INTO oauth_oidc_providers (
			tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`, tenantB, providerName, "client-id-b", rawCiphertext, config.AuthURL, config.TokenURL, config.Issuer, config.JWKSURL, "openid email")
	require.NoError(t, err)

	// Attempting to read under tenant-b must fail due to AAD mismatch
	_, err = store.GetProvider(ctx, tenantB, providerName)
	require.Error(t, err, "reading transposed secret under tenant-b must fail due to AAD mismatch")
}

// TestPgxStore_SEC_OAU_02_LegacyFallbackWithoutAAD verifies backward compatibility:
// legacy secrets sealed without AAD can still be decrypted via fallback.
func TestPgxStore_SEC_OAU_02_LegacyFallbackWithoutAAD(t *testing.T) {
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
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, oauthpgx.Migrate(ctx, pool))

	dummyKey := make([]byte, 32)
	k, err := keystore.NewKEK(dummyKey)
	require.NoError(t, err)

	store := oauthpgx.NewStore(pool, wrappedKEK{k})
	const tenantLegacy = "tenant-legacy"
	const providerName = "sso-legacy"

	const legacySecret = "legacy-unauthenticated-secret"
	// Seal without AAD (legacy behavior)
	sealed, err := k.Seal([]byte(legacySecret))
	require.NoError(t, err)
	sealedB64 := base64.StdEncoding.EncodeToString(sealed)

	_, err = pool.Exec(ctx, `
		INSERT INTO oauth_oidc_providers (
			tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`, tenantLegacy, providerName, "client-id-legacy", sealedB64, "https://sso.example.com/auth", "https://sso.example.com/token", "https://sso.example.com", "https://sso.example.com/jwks", "openid email")
	require.NoError(t, err)

	p, err := store.GetProvider(ctx, tenantLegacy, providerName)
	require.NoError(t, err, "legacy secret without AAD must be opened successfully via fallback")
	require.Equal(t, providerName, p.Name())
}
