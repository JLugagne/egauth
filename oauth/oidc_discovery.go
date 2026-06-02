package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// validateOIDCEndpointURL validates an OIDC endpoint URL (issuer, token, auth or JWKS).
//
// By default it requires a non-empty https URL whose host is not a literal internal IP, reusing
// ValidateExternalURL — the same secure-by-default gate the SSRF fix applies. When allowInsecure
// is true (the dev-only WithInsecureURLs / OIDCConfig.AllowInsecureURLs opt-in) the https
// requirement is dropped: the URL must still parse and carry an http/https scheme and a host,
// but a loopback http IdP becomes acceptable for local development.
func validateOIDCEndpointURL(rawURL string, allowInsecure bool) error {
	if !allowInsecure {
		return ValidateExternalURL(rawURL)
	}
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%w: empty URL", ErrBlockedURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlockedURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not allowed", ErrBlockedURL, u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: missing host", ErrBlockedURL)
	}
	return nil
}

// sameHost reports whether two URLs share the same host (case-insensitive, port-insensitive).
// It is the defence-in-depth check that binds a JWKS / jwks_uri to its issuer.
func sameHost(a, b string) bool {
	ua, err := url.Parse(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	ub, err := url.Parse(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	ha, hb := ua.Hostname(), ub.Hostname()
	return ha != "" && strings.EqualFold(ha, hb)
}

// oidcDiscoveryDocument is the subset of the OIDC discovery metadata we consume.
type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKSURL resolves an issuer's authoritative jwks_uri via OIDC discovery. It fetches
// <issuer>/.well-known/openid-configuration over client, requires the document's "issuer" to
// equal the configured issuer exactly (OIDC discovery rule), and binds the returned jwks_uri to
// the issuer host. The supplied client is the SSRF-safe client on the untrusted/dynamic path.
func discoverJWKSURL(ctx context.Context, client *http.Client, issuer string, allowInsecure bool) (string, error) {
	if err := validateOIDCEndpointURL(issuer, allowInsecure); err != nil {
		return "", fmt.Errorf("invalid issuer: %w", err)
	}
	discoveryURL := strings.TrimRight(strings.TrimSpace(issuer), "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: building discovery request: %v", ErrIDTokenInvalid, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: fetching OIDC discovery: %v", ErrIDTokenInvalid, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: discovery endpoint status %d", ErrIDTokenInvalid, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return "", fmt.Errorf("%w: reading discovery document: %v", ErrIDTokenInvalid, err)
	}
	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("%w: decoding discovery document: %v", ErrIDTokenInvalid, err)
	}

	// OIDC discovery requires the document's issuer to equal the requested issuer exactly.
	if strings.TrimSpace(doc.Issuer) != strings.TrimSpace(issuer) {
		return "", fmt.Errorf("%w: discovery issuer %q != configured issuer %q", ErrJWKSHostMismatch, doc.Issuer, issuer)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return "", fmt.Errorf("%w: discovery document has no jwks_uri", ErrIDTokenInvalid)
	}
	if err := validateOIDCEndpointURL(doc.JWKSURI, allowInsecure); err != nil {
		return "", fmt.Errorf("invalid jwks_uri: %w", err)
	}
	// Defence in depth: the keys must come from the issuer's own host.
	if !sameHost(doc.JWKSURI, issuer) {
		return "", fmt.Errorf("%w: jwks_uri host does not match issuer host", ErrJWKSHostMismatch)
	}
	return doc.JWKSURI, nil
}
