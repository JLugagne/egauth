// Package providers builds the federation.Provider specs of well-known identity providers. Every
// constructor refuses an empty client ID and returns a validated spec. Fixed-issuer providers pin
// their own issuer and JWKS; the issuer is never derived from an authorization URL. Adjust the
// returned value (Name, Scopes, Domains) directly; the configuration is validated again at New.
//
// # Stability
//
// Stability class: experimental. No SemVer guarantee: the API may change or be removed in any
// release. See docs/adr/0001-v1-scope-and-stability-classes.md.
package providers

import (
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/JLugagne/egauth/federation"
)

// Client is the OAuth client registered at a provider. ID must not be empty. Secret is zero for a
// public client; for Apple it is the signed client-secret JWT.
type Client struct {
	ID     string
	Secret federation.Secret
}

// String redacts the secret.
func (c Client) String() string { return "providers.Client{" + c.ID + "}" }

// GoString redacts the secret.
func (c Client) GoString() string { return c.String() }

// LogValue logs the client by ID only.
func (c Client) LogValue() slog.Value { return slog.StringValue(c.ID) }

var (
	labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	guidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	poolPattern  = regexp.MustCompile(`^([a-z]{2}(-[a-z]+)+-[0-9])_[A-Za-z0-9]+$`)
)

func build(base federation.Provider, c Client) (federation.Provider, error) {
	if c.ID == "" {
		return federation.Provider{}, invalidArg("client id is empty")
	}
	base.ClientID = c.ID
	base.ClientSecret = c.Secret
	if err := base.Validate(); err != nil {
		return federation.Provider{}, err
	}
	return base, nil
}

func label(field, v string) error {
	if !labelPattern.MatchString(v) {
		return invalidArg(field + " is not a plain identifier")
	}
	return nil
}

func hostOnly(field, domain string) (string, error) {
	d := strings.TrimSpace(domain)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	u, err := url.Parse("https://" + d)
	if err != nil || d == "" || strings.ContainsAny(d, "?#") || u.Host != d || u.Hostname() == "" || u.Path != "" || u.User != nil {
		return "", invalidArg(field + " must be a bare host")
	}
	return d, nil
}

func baseURL(field, raw string) (string, error) {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || strings.ContainsAny(raw, "?#") || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", invalidArg(field + " must be an https base url")
	}
	return raw, nil
}

func invalidArg(msg string) error {
	return errors.Join(federation.ErrInvalidProvider, errors.New(msg))
}

func oidcScopes() []string { return []string{"openid", "email", "profile"} }
