package pgx

import (
	"context"
	"embed"
	"errors"
	"fmt"
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
	// issuerAllowlist, when non-empty, restricts which OIDC issuers a tenant may register or use.
	// Empty (the default) means allow all, preserving existing single-operator setups.
	issuerAllowlist map[string]struct{}
}

// StoreOption configures a Store at construction.
type StoreOption func(*Store)

// WithIssuerAllowlist restricts which OIDC issuers may be registered (UpsertProvider) or
// resolved (GetProvider). It is OFF by default (an empty or nil list allows every issuer, so
// existing single-operator deployments are unaffected). When set, any issuer not on the list is
// rejected with ErrIssuerNotAllowed — an opt-in defence-in-depth control for operators who want
// to constrain the bring-your-own-SSO surface to a vetted set of identity providers.
func WithIssuerAllowlist(issuers []string) StoreOption {
	return func(s *Store) {
		if len(issuers) == 0 {
			return
		}
		allow := make(map[string]struct{}, len(issuers))
		for _, iss := range issuers {
			allow[strings.TrimSpace(iss)] = struct{}{}
		}
		s.issuerAllowlist = allow
	}
}

// ErrIssuerNotAllowed is returned when an OIDC issuer is not on a configured issuer allowlist.
var ErrIssuerNotAllowed = errors.New("oauth/pgx: issuer not on allowlist")

// NewStore creates a new PostgreSQL store for OAuth providers. Pass StoreOptions such as
// WithIssuerAllowlist to harden the multi-tenant configuration surface.
func NewStore(pool *pgxpool.Pool, opts ...StoreOption) *Store {
	s := &Store{pool: pool}
	for _, o := range opts {
		o(s)
	}
	return s
}

// checkIssuerAllowed enforces the optional issuer allowlist. It is a no-op when no allowlist is
// configured.
func (s *Store) checkIssuerAllowed(issuer string) error {
	if len(s.issuerAllowlist) == 0 {
		return nil
	}
	if _, ok := s.issuerAllowlist[strings.TrimSpace(issuer)]; !ok {
		return fmt.Errorf("%w: %q", ErrIssuerNotAllowed, issuer)
	}
	return nil
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

	// Defence in depth: reject a stored issuer that is no longer on the operator allowlist.
	if err := s.checkIssuerAllowed(issuer); err != nil {
		return nil, err
	}

	scopes := strings.Fields(scopesStr)

	// Since this store enforces OIDC, the fetchUser is never called (OIDC id_token verification bypasses it).
	var fetch oauth.FetchUserFunc = func(ctx context.Context, client *http.Client, accessToken string) (*oauth.UserInfo, error) {
		return nil, errors.New("unreachable: OIDC bypasses fetchUser")
	}

	// These URLs come from tenant-controlled storage in the bring-your-own-SSO model, so every
	// server-side fetch (OIDC discovery, JWKS verification and the token exchange that carries the
	// client_secret) must go through the SSRF-hardened client whose dialer blocks internal/loopback
	// addresses at dial time. UpsertProvider also validates the URLs at registration, but the
	// dial-time guard is the authoritative defence against DNS rebinding.
	safeClient := oauth.SafeHTTPClient()
	// JWKSURL is intentionally omitted: the verifier discovers the authoritative jwks_uri from the
	// issuer's OIDC discovery document, so a tenant cannot bind a trusted issuer to foreign keys.
	cfg := oauth.OIDCConfig{
		Issuer:     issuer,
		HTTPClient: safeClient,
	}

	p := oauth.New(providerName, clientID, clientSecret, authURL, tokenURL, scopes, fetch,
		oauth.WithHTTPClient(safeClient), oauth.WithOIDC(cfg))
	return p, nil
}

// UpsertProvider configures an OIDC connection for a given tenant.
func (s *Store) UpsertProvider(ctx context.Context, tenantID, providerName string, config OIDCProviderConfig) error {
	if err := s.checkIssuerAllowed(config.Issuer); err != nil {
		return err
	}
	if err := validateProviderURLs(config); err != nil {
		return err
	}
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

// validateProviderURLs rejects a provider registration whose URLs are unusable or point at an
// internal/loopback host. In the bring-your-own-SSO model these URLs are tenant-controlled and
// later fetched server-side (OIDC discovery, JWKS verification and the token exchange that carries
// the client_secret), so a literal http:// or loopback/metadata target is an SSRF vector. Each URL
// must be a non-empty https URL whose host is not a literal internal IP; the dial-time guard in
// oauth.SafeHTTPClient remains the authoritative defence against DNS rebinding.
//
// jwks_url is validated when supplied but is optional: the verifier prefers OIDC discovery and
// only accepts an explicit jwks_url whose host matches the issuer.
func validateProviderURLs(config OIDCProviderConfig) error {
	required := []struct {
		name string
		url  string
	}{
		{"auth_url", config.AuthURL},
		{"token_url", config.TokenURL},
		{"issuer", config.Issuer},
	}
	for _, f := range required {
		if err := oauth.ValidateExternalURL(f.url); err != nil {
			return fmt.Errorf("invalid %s: %w", f.name, err)
		}
	}
	if strings.TrimSpace(config.JWKSURL) != "" {
		if err := oauth.ValidateExternalURL(config.JWKSURL); err != nil {
			return fmt.Errorf("invalid jwks_url: %w", err)
		}
	}
	return nil
}
