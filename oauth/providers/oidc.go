package providers

import (
	"context"
	"encoding/json"
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

// WithDiscoveryHTTPClient overrides the HTTP client used to fetch the discovery document. The
// default is oauth.SafeHTTPClient() — the SSRF dial guard applies and 3xx responses are never
// followed (issue #117); a plain 10s-timeout client is used only under WithInsecureDiscoveryURLs
// (dev). Override it to supply a custom transport or, in tests, a client pointed at a stub server.
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
// on the issuer but still requires a parseable http/https URL with a non-empty host, and the
// default discovery client falls back to a plain client (the SSRF-safe default would block the
// loopback IdP at dial time).
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
		scopes: []string{"openid", "email", "profile"},
		name:   "oidc",
	}
	for _, o := range opts {
		o(&settings)
	}
	// SEC-SSRF (issue #117): the discovery client defaults to the SSRF-safe client — the same
	// dial-time internal-IP guard and 3xx rejection as the untrusted dynamic path — so a
	// misbehaving or compromised issuer cannot pivot the discovery GET onto internal targets via
	// a redirect. The plain client is reserved for the WithInsecureDiscoveryURLs dev opt-in, where
	// the safe client would block the local loopback IdP at dial time. An explicit
	// WithDiscoveryHTTPClient override always wins.
	if settings.httpClient == nil {
		if settings.allowInsecureURLs {
			settings.httpClient = &http.Client{Timeout: 10 * time.Second}
		} else {
			settings.httpClient = oauth.SafeHTTPClient()
		}
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
// issuer URL via oauth.ValidateOIDCEndpointURL before issuing any network request, and
// post-validates every discovered endpoint (authorization_endpoint, token_endpoint,
// userinfo_endpoint) with oauth.ValidateOIDCEndpointURL before use (issue #117), matching the
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
		return nil, fmt.Errorf("oidc discovery: document missing authorization_endpoint or token_endpoint")
	}
	// SEC-SSRF (issue #117): the discovered endpoints are fetched server-side later (auth
	// redirect, token POST carrying the client secret, userinfo GET carrying the access token),
	// so each must pass the same https/SSRF gate as the issuer before use. oauth.New re-checks
	// auth/token; the userinfo URL has no other gate (and is spec-optional), so this is where a
	// non-https or internal-literal userinfo_endpoint fails closed.
	endpoints := []struct{ field, url string }{
		{"authorization_endpoint", doc.AuthorizationEndpoint},
		{"token_endpoint", doc.TokenEndpoint},
		{"userinfo_endpoint", doc.UserInfoEndpoint},
	}
	for _, e := range endpoints {
		if e.url == "" {
			continue
		}
		if err := oauth.ValidateOIDCEndpointURL(e.url, allowInsecure); err != nil {
			return nil, fmt.Errorf("oidc discovery: invalid %s: %w", e.field, err)
		}
	}
	return &doc, nil
}
