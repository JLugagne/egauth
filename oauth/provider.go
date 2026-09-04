// Package oauth implements the OAuth2 authorization-code flow (with PKCE) as stateless,
// composable HTTP handlers. Ready-made Google, GitHub and Discord providers live
// in the oauth/providers subpackage; the generic New constructor here covers any other
// compliant provider. Following egauth's philosophy
// the package is HTTP-decentralized (it exposes handler builders, not a router) and depends
// only on the standard library plus the egauth identity/tokens packages — no third-party
// OAuth SDK.
package oauth

import (
	"bytes"
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
	name              string
	clientID          string
	clientSecret      string
	authURL           string
	tokenURL          string
	scopes            []string
	httpClient        *http.Client
	fetchUser         FetchUserFunc
	oidc              *oidcVerifier // non-nil when OIDC id_token validation is enabled (WithOIDC)
	allowInsecureURLs bool          // dev-only: permit non-https auth/token URLs (WithInsecureURLs)
	configErr         error         // deferred construction error (e.g. a non-https endpoint URL)
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

// WithOIDC enables OpenID Connect id_token validation for the provider (see OIDCConfig). With it
// the callback flow gains true OIDC: BeginHandler mints a nonce bound through the state cookie,
// and Exchange validates the id_token's signature (against the issuer's JWKS) and its
// iss/aud/exp/iat/nonce claims, deriving the UserInfo from the verified claims rather than from
// an access-token userinfo GET. The nonce is mandatory, so a direct Exchange caller on an
// OIDC-enabled provider must pass WithExpectedNonce.
//
// An invalid OIDCConfig (empty Issuer, a JWKSURL whose host differs from the issuer, or no
// resolvable audience) does NOT panic: WithOIDC runs synchronously inside New, and on the
// per-request dynamic ProviderStore a panic would break the login route. Instead the error is
// recorded as a deferred configErr (the same mechanism New uses for a non-https endpoint URL)
// and surfaced when the provider is first used (Exchange); oidcEnabled stays false so the
// provider fails closed rather than nil-derefing the verifier.
func WithOIDC(cfg OIDCConfig) ProviderOption {
	return func(p *Provider) {
		v, err := newOIDCVerifier(cfg, p.clientID)
		if err != nil {
			// PANIC-01: WithOIDC runs synchronously inside New, and on the dynamic
			// ProviderStore that is per request over tenant-controlled data. A panic there
			// breaks the login route, so an invalid OIDCConfig is instead recorded as a
			// deferred construction error (surfaced by Exchange) — mirroring the non-https
			// endpoint configErr set in New. Don't clobber an already-recorded configErr.
			if p.configErr == nil {
				p.configErr = fmt.Errorf("oauth: WithOIDC: %w", err)
			}
			return
		}
		p.oidc = v
	}
}

// New builds a Provider for any RFC 6749 authorization-code provider. The ready-made
// Google/GitHub/Discord constructors in the oauth/providers subpackage are thin wrappers over
// it.
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
	// SEC-06: the authorization and token endpoints must be https by default. The dev-only
	// WithInsecureURLs opt-in relaxes this. The check runs after options so the flag is honoured.
	// New cannot return an error (it is the package's fundamental constructor), so an invalid
	// endpoint is recorded as a deferred configErr surfaced eagerly by AuthCodeURL/Exchange.
	// A WithOIDC option may already have recorded a deferred configErr; preserve the first one
	// (the existing convention) rather than overwriting it with an endpoint-URL error.
	for _, f := range []string{p.authURL, p.tokenURL} {
		if p.configErr != nil {
			break
		}
		if err := validateOIDCEndpointURL(f, p.allowInsecureURLs); err != nil {
			p.configErr = fmt.Errorf("oauth: invalid provider endpoint URL: %w", err)
			break
		}
	}
	return p
}

// Name returns the provider key (e.g. "google"). It is stored as the identity's Provider.
func (p *Provider) Name() string { return p.name }

// oidcEnabled reports whether OIDC id_token validation is configured (WithOIDC).
func (p *Provider) oidcEnabled() bool { return p.oidc != nil }

// AuthCodeOption customizes the authorization URL.
type AuthCodeOption func(*authCodeParams)

type authCodeParams struct {
	nonce string
}

// WithAuthNonce adds an OIDC nonce parameter to the authorization URL. The handler sets it
// automatically for OIDC-enabled providers; supply it manually only when driving AuthCodeURL
// directly.
func WithAuthNonce(nonce string) AuthCodeOption {
	return func(a *authCodeParams) { a.nonce = nonce }
}

// AuthCodeURL builds the provider authorization URL for the given state, redirect URI and
// (optional) PKCE S256 challenge. Pass WithAuthNonce to include an OIDC nonce.
func (p *Provider) AuthCodeURL(state, redirectURI, codeChallenge string, opts ...AuthCodeOption) string {
	var params authCodeParams
	for _, opt := range opts {
		opt(&params)
	}
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
	if params.nonce != "" {
		v.Set("nonce", params.nonce)
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return p.authURL + sep + v.Encode()
}

// tokenResponse is the subset of the token-endpoint response egauth uses.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

// ExchangeOption customizes a token exchange.
type ExchangeOption func(*exchangeParams)

type exchangeParams struct {
	nonce string
}

// WithExpectedNonce supplies the nonce the id_token must echo, for an OIDC-enabled provider. The
// callback handler sets it automatically from the state cookie; supply it manually only when
// driving Exchange directly. It is ignored by non-OIDC providers.
func WithExpectedNonce(nonce string) ExchangeOption {
	return func(e *exchangeParams) { e.nonce = nonce }
}

// Exchange swaps an authorization code (with its PKCE verifier, if any) for the provider's
// normalized user info. The token endpoint is always called over the provider's configured
// (HTTPS) URL with the client secret; the access token never leaves this method.
//
// For an OIDC-enabled provider (WithOIDC) the id_token from the token response is validated
// (signature + iss/aud/exp/iat/nonce) and the UserInfo is derived from its verified claims; the
// expected nonce is supplied with WithExpectedNonce.
func (p *Provider) Exchange(ctx context.Context, code, redirectURI, codeVerifier string, opts ...ExchangeOption) (*UserInfo, error) {
	var params exchangeParams
	if p.configErr != nil {
		return nil, p.configErr
	}
	for _, opt := range opts {
		opt(&params)
	}

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
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: token endpoint status %d", ErrExchangeFailed, resp.StatusCode)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("%w: decode token response: %v", ErrExchangeFailed, err)
	}

	// OIDC: trust the cryptographically-attested id_token claims (with nonce replay protection)
	// rather than an access-token userinfo GET.
	if p.oidc != nil {
		if tok.IDToken == "" {
			return nil, fmt.Errorf("%w: provider returned no id_token", ErrExchangeFailed)
		}
		return p.oidc.verify(ctx, tok.IDToken, params.nonce)
	}

	if tok.AccessToken == "" {
		return nil, fmt.Errorf("%w: empty access token", ErrExchangeFailed)
	}
	return p.fetchUser(ctx, p.httpClient, tok.AccessToken)
}

// GetJSON performs a bearer-authenticated GET and decodes a JSON response into dst. It sets a
// User-Agent (required by some providers, notably GitHub) and bounds the response size. It is
// exported so provider implementations outside this package (see oauth/providers) can reuse the
// same hardened fetch behaviour.
func GetJSON(ctx context.Context, c *http.Client, rawURL, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "egauth")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: userinfo status %d", ErrUserInfoFailed, resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfoFailed, err)
	}
	return nil
}

// WithInsecureURLs opts INTO accepting non-https provider URLs (auth, token, and — for an
// OIDC-enabled provider — the issuer / JWKS / discovery URLs). It exists ONLY for local
// development against an http loopback IdP and must never be set in production: by default the
// provider rejects non-https endpoints (SEC-06). It is the URL counterpart of the loud,
// secure-by-default WithInsecureCookies. When set, an OIDC-enabled provider also needs the same
// opt-in on its OIDCConfig (AllowInsecureURLs).
func WithInsecureURLs() ProviderOption {
	return func(p *Provider) { p.allowInsecureURLs = true }
}
