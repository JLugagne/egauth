package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/JLugagne/egauth/oauth"
)

// discoveryMaxBytes bounds the OIDC discovery document read so a hostile or broken issuer cannot
// stream an unbounded body into memory during construction.
const discoveryMaxBytes = 1 << 20 // 1 MiB

// OIDCOption configures the generic OIDC constructor (distinct from oauth.ProviderOption, which
// configures the resulting Provider).
type OIDCOption func(*oidcSettings)

type oidcSettings struct {
	httpClient        *http.Client
	scopes            []string
	name              string
	allowInsecureURLs bool
}

// WithDiscoveryHTTPClient overrides the HTTP client used to fetch the discovery document. On an
// untrusted/dynamic path supply oauth.SafeHTTPClient(); the default is a plain 10s-timeout
// client suitable for a trusted, statically-configured issuer.
func WithDiscoveryHTTPClient(c *http.Client) OIDCOption {
	return func(s *oidcSettings) { s.httpClient = c }
}

// WithOIDCScopes overrides the default scopes ({"openid", "email", "profile"}) requested by the
// generic OIDC provider.
func WithOIDCScopes(scopes ...string) OIDCOption {
	return func(s *oidcSettings) { s.scopes = scopes }
}

// WithProviderName overrides the provider name recorded on the Provider (default "oidc"). The
// name is the stable key under which identities from this provider are linked, so set a stable,
// descriptive value (for example "zitadel" or "onelogin") when wiring a specific IdP.
func WithProviderName(name string) OIDCOption {
	return func(s *oidcSettings) { s.name = name }
}

// WithInsecureDiscoveryURLs opts INTO accepting a non-https issuer URL during discovery. It
// mirrors oauth.WithInsecureURLs and exists ONLY for local development against an http loopback
// IdP — never set this in production. When set, fetchOIDCDiscovery skips the https requirement
// on the issuer but still requires a parseable http/https URL with a non-empty host.
func WithInsecureDiscoveryURLs() OIDCOption {
	return func(s *oidcSettings) { s.allowInsecureURLs = true }
}

// OIDC builds a Provider for any standards-compliant OpenID Connect issuer by resolving its
// endpoints from the issuer's discovery document ({issuer}/.well-known/openid-configuration).
// This is the universal escape hatch for IdPs without a dedicated constructor — Zitadel, Ping,
// OneLogin, Curity, Dex, and so on.
//
// Discovery is performed once, synchronously, during construction. If it fails (network error,
// non-2xx, malformed document, or a discovered endpoint that fails the https/SSRF checks in
// oauth.New) the error is deferred onto the Provider and surfaced when AuthCodeURL or Exchange is
// first called, mirroring oauth.New's own deferred-configErr behaviour — construction never
// panics. Because it makes a network call, do NOT call OIDC per request on a hot path; build the
// Provider once at startup (or memoize it in your ProviderStore).
//
// For id_token validation, additionally pass oauth.WithOIDC via an oauth.ProviderOption. The
// issuer you pass here is exactly the value to use as OIDCConfig.Issuer, and you can leave
// OIDCConfig.JWKSURL empty to let the verifier discover the jwks_uri itself:
//
//	p := providers.OIDC(ctx, issuer, id, secret,
//	    []oauth.ProviderOption{oauth.WithOIDC(oauth.OIDCConfig{Issuer: issuer})},
//	)
func OIDC(ctx context.Context, issuer, clientID, clientSecret string, providerOpts []oauth.ProviderOption, opts ...OIDCOption) *oauth.Provider {
	settings := oidcSettings{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		scopes:     []string{"openid", "email", "profile"},
		name:       "oidc",
	}
	for _, o := range opts {
		o(&settings)
	}

	meta, err := fetchOIDCDiscovery(ctx, settings.httpClient, issuer, settings.allowInsecureURLs)
	if err != nil {
		// Defer the error: oauth.New records a configErr for empty/invalid endpoints, which
		// AuthCodeURL and Exchange surface. We stash the discovery error on the name so it is not
		// silently swallowed — but the canonical failure path is the deferred endpoint validation.
		return oauth.New(settings.name, clientID, clientSecret, "", "",
			settings.scopes, oidcUserInfoFetcher(""), providerOpts...)
	}
	return oauth.New(settings.name, clientID, clientSecret,
		meta.AuthorizationEndpoint, meta.TokenEndpoint,
		settings.scopes, oidcUserInfoFetcher(meta.UserInfoEndpoint), providerOpts...)
}

// oidcDiscoveryDocument is the subset of the OIDC discovery metadata this package consumes.
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// fetchOIDCDiscovery retrieves and validates the issuer's discovery document. It enforces the
// OIDC requirement that the document's "issuer" exactly equals the requested issuer (preventing
// a discovery document from redirecting trust to a different issuer). It pre-validates the
// issuer URL via oauth.ValidateOIDCEndpointURL before issuing any network request, matching the
// https/SSRF gate on the dynamic/untrusted path. When allowInsecure is true (the dev-only
// WithInsecureDiscoveryURLs opt-in) the https requirement is relaxed to permit a loopback http
// IdP for local development.
func fetchOIDCDiscovery(ctx context.Context, c *http.Client, issuer string, allowInsecure bool) (*oidcDiscoveryDocument, error) {
	if err := oauth.ValidateOIDCEndpointURL(issuer, allowInsecure); err != nil {
		return nil, fmt.Errorf("oidc discovery: invalid issuer: %w", err)
	}
	configURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, discoveryMaxBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc discovery: decode document: %w", err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("oidc discovery: document issuer %q does not match requested issuer %q", doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, errors.New("oidc discovery: document missing authorization_endpoint or token_endpoint")
	}
	return &doc, nil
}
