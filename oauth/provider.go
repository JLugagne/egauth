// Package oauth implements the OAuth2 authorization-code flow (with PKCE) as stateless,
// composable HTTP handlers. It ships ready-made Google, GitHub and Discord providers and a
// generic New constructor for any other compliant provider. Following libauth's philosophy
// the package is HTTP-decentralized (it exposes handler builders, not a router) and depends
// only on the standard library plus the libauth identity/tokens packages — no third-party
// OAuth SDK.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes caps how much of a provider response we read, to bound memory use.
const maxResponseBytes = 1 << 20

// UserInfo is the normalized identity returned by a provider after a successful exchange.
type UserInfo struct {
	// ProviderID is the stable, unique identifier of the user at the provider (the OIDC
	// "sub", GitHub's numeric id, Discord's snowflake, ...). It is used as the identity's
	// ProviderID and never changes for a given account, unlike the email.
	ProviderID string
	// Email is the user's email at the provider (may be empty if no scope/grant).
	Email string
	// EmailVerified reports whether the provider considers the email verified.
	EmailVerified bool
	// Name is an optional human-readable display name.
	Name string
}

// FetchUserFunc retrieves and normalizes a provider's user profile using an access token.
// Custom providers supply one to New; the built-in providers each have their own.
type FetchUserFunc func(ctx context.Context, client *http.Client, accessToken string) (*UserInfo, error)

// Provider is a configured OAuth2 authorization-code provider.
type Provider struct {
	name         string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	scopes       []string
	httpClient   *http.Client
	fetchUser    FetchUserFunc
}

// ProviderOption customizes a Provider at construction.
type ProviderOption func(*Provider)

// WithScopes overrides the default scopes the provider requests.
func WithScopes(scopes ...string) ProviderOption {
	return func(p *Provider) { p.scopes = scopes }
}

// WithHTTPClient sets the HTTP client used for the token exchange and the user-info request
// (default: a client with a 10s timeout). Useful to inject a custom transport or, in tests,
// a client pointed at a stub server.
func WithHTTPClient(c *http.Client) ProviderOption {
	return func(p *Provider) { p.httpClient = c }
}

// New builds a Provider for any RFC 6749 authorization-code provider. The built-in
// Google/GitHub/Discord constructors are thin wrappers over it.
func New(name, clientID, clientSecret, authURL, tokenURL string, scopes []string, fetch FetchUserFunc, opts ...ProviderOption) *Provider {
	p := &Provider{
		name:         name,
		clientID:     clientID,
		clientSecret: clientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		scopes:       scopes,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		fetchUser:    fetch,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns the provider key (e.g. "google"). It is stored as the identity's Provider.
func (p *Provider) Name() string { return p.name }

// AuthCodeURL builds the provider authorization URL for the given state, redirect URI and
// (optional) PKCE S256 challenge.
func (p *Provider) AuthCodeURL(state, redirectURI, codeChallenge string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", strings.Join(p.scopes, " "))
	v.Set("state", state)
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return p.authURL + sep + v.Encode()
}

// tokenResponse is the subset of the token-endpoint response libauth uses.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Exchange swaps an authorization code (with its PKCE verifier, if any) for the provider's
// normalized user info. The token endpoint is always called over the provider's configured
// (HTTPS) URL with the client secret; the access token never leaves this method.
func (p *Provider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*UserInfo, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: token endpoint status %d", ErrExchangeFailed, resp.StatusCode)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("%w: decode token response: %v", ErrExchangeFailed, err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("%w: empty access token", ErrExchangeFailed)
	}

	return p.fetchUser(ctx, p.httpClient, tok.AccessToken)
}

// getJSON performs a bearer-authenticated GET and decodes a JSON response into dst. It sets a
// User-Agent (required by some providers, notably GitHub) and bounds the response size.
func getJSON(ctx context.Context, c *http.Client, rawURL, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "libauth")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: userinfo status %d", ErrUserInfoFailed, resp.StatusCode)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}
	return nil
}
