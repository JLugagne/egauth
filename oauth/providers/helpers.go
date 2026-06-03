package providers

import "strings"

// normalizeHTTPSDomain turns a bare domain ("tenant.example.com"), or one that already carries a
// scheme, into an https base URL with no trailing slash. It is used by the per-tenant providers
// (Auth0, Keycloak, Cognito, generic OIDC) that accept a domain/base-URL argument.
func normalizeHTTPSDomain(domain string) string {
	domain = strings.TrimRight(strings.TrimSpace(domain), "/")
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}
	return domain
}
