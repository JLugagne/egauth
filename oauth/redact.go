package oauth

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// Provider carries the OAuth2 client_secret in an unexported field. Dumping a provider
// (log.Printf("%+v", p), slog.Any) would print the secret, which the package otherwise keeps out
// of every error and request path. The methods below make the common accidental-leak paths safe
// by default: fmt verbs (%v/%s/%+v/%#v) and slog (via slog.LogValuer) render the client secret as
// a placeholder, while the non-secret identifying fields (name, client ID, endpoints, scopes) stay
// visible to aid debugging.
//
// NOTE: JSON marshalling is intentionally NOT redacted — Provider has no json tags and is never
// serialized by egauth. Treat the client secret as a credential and never log or serialize the
// provider. See SECURITY.md.

// String renders the Provider with the client secret redacted.
func (p Provider) String() string {
	clientSecret := redacted
	if p.clientSecret == "" {
		clientSecret = "" // distinguish "unset" from "set-but-hidden" without leaking
	}
	return fmt.Sprintf(
		"Provider{Name:%s ClientID:%s ClientSecret:%s AuthURL:%s TokenURL:%s Scopes:%v "+
			"OIDCEnabled:%t AllowInsecureURLs:%t ExpectedIssuer:%s ConfigErrSet:%t}",
		p.name, p.clientID, clientSecret, p.authURL, p.tokenURL, p.scopes,
		p.oidc != nil, p.allowInsecureURLs, p.expectedIssuer, p.configErr != nil,
	)
}

// GoString redacts the %#v representation.
func (p Provider) GoString() string { return p.String() }

// LogValue redacts the Provider for structured (slog) logging.
func (p Provider) LogValue() slog.Value {
	clientSecret := redacted
	if p.clientSecret == "" {
		clientSecret = ""
	}
	return slog.GroupValue(
		slog.String("name", p.name),
		slog.String("client_id", p.clientID),
		slog.String("client_secret", clientSecret),
		slog.String("auth_url", p.authURL),
		slog.String("token_url", p.tokenURL),
		slog.Any("scopes", p.scopes),
		slog.Bool("oidc_enabled", p.oidc != nil),
		slog.Bool("allow_insecure_urls", p.allowInsecureURLs),
	)
}
