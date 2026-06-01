package pgx

import (
	"context"
	"embed"
	"errors"
	"net/http"
	"strings"

	"github.com/JLugagne/egauth/internal/pgxmigrate"
	"github.com/JLugagne/egauth/oauth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies the SQL schema migrations for the OAuth pgx store.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return pgxmigrate.Run(ctx, pool, migrationsFS)
}

// OIDCProviderConfig holds the database-storable attributes of an OIDC connection.
type OIDCProviderConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Issuer       string
	JWKSURL      string
	Scopes       []string
}

// Store is a PostgreSQL-backed implementation of oauth.ProviderStore.
// It retrieves OIDC provider configurations dynamically per-tenant.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new PostgreSQL store for OAuth providers.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// GetProvider retrieves a provider configuration for a specific tenant and builds an OIDC provider.
func (s *Store) GetProvider(ctx context.Context, tenantID, providerName string) (*oauth.Provider, error) {
	query := `
		SELECT client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes
		FROM oauth_oidc_providers
		WHERE tenant_id = $1 AND provider_name = $2
	`
	var (
		clientID, clientSecret, authURL, tokenURL, issuer, jwksURL, scopesStr string
	)
	err := s.pool.QueryRow(ctx, query, tenantID, providerName).Scan(
		&clientID, &clientSecret, &authURL, &tokenURL, &issuer, &jwksURL, &scopesStr,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, oauth.ErrProviderNotFound
		}
		return nil, err
	}

	scopes := strings.Fields(scopesStr)

	// Since this store enforces OIDC, the fetchUser is never called (OIDC id_token verification bypasses it).
	var fetch oauth.FetchUserFunc = func(ctx context.Context, client *http.Client, accessToken string) (*oauth.UserInfo, error) {
		return nil, errors.New("unreachable: OIDC bypasses fetchUser")
	}

	cfg := oauth.OIDCConfig{
		Issuer:  issuer,
		JWKSURL: jwksURL,
	}

	p := oauth.New(providerName, clientID, clientSecret, authURL, tokenURL, scopes, fetch, oauth.WithOIDC(cfg))
	return p, nil
}

// UpsertProvider configures an OIDC connection for a given tenant.
func (s *Store) UpsertProvider(ctx context.Context, tenantID, providerName string, config OIDCProviderConfig) error {
	query := `
		INSERT INTO oauth_oidc_providers (
			tenant_id, provider_name, client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, provider_name) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			client_secret = EXCLUDED.client_secret,
			auth_url = EXCLUDED.auth_url,
			token_url = EXCLUDED.token_url,
			issuer = EXCLUDED.issuer,
			jwks_url = EXCLUDED.jwks_url,
			scopes = EXCLUDED.scopes,
			updated_at = NOW()
	`
	_, err := s.pool.Exec(ctx, query,
		tenantID, providerName,
		config.ClientID, config.ClientSecret,
		config.AuthURL, config.TokenURL,
		config.Issuer, config.JWKSURL, strings.Join(config.Scopes, " "),
	)
	return err
}

// DeleteProvider removes a configured provider for a given tenant.
func (s *Store) DeleteProvider(ctx context.Context, tenantID, providerName string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_oidc_providers WHERE tenant_id = $1 AND provider_name = $2`, tenantID, providerName)
	return err
}
