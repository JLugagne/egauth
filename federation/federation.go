// Package federation defines the value spec of an OAuth or OIDC identity provider. A Provider
// carries its own issuer and JWKS: neither is ever derived from the authorization URL.
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package federation

import (
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/JLugagne/egauth/principal"
	storefed "github.com/JLugagne/egauth/store/federation"
)

// EmailVerification tells how far a provider's email claim is trusted. It is the persisted type of
// the federation store. Every value needs a true email_verified claim; see Provider.Verified.
type EmailVerification = storefed.EmailVerification

const (
	// Never ignores the provider's email claim.
	Never = storefed.Never
	// ClaimBased trusts the email_verified claim for emails of the spec's Domains only. Without
	// Domains it trusts no email.
	ClaimBased = storefed.ClaimBased
	// Always trusts the email_verified claim whatever the email's domain. It never upgrades a false
	// or absent claim.
	Always = storefed.Always
)

// ErrInvalidProvider is joined into every validation failure of a Provider.
var ErrInvalidProvider = errors.New("federation: invalid provider")

// ErrDomainsSystemOnly reports that a non-system caller tried to set Domains on a runtime spec. It
// is joined with ErrInvalidProvider.
var ErrDomainsSystemOnly = errors.New("federation: only a system caller may set provider domains")

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Secret is a client secret held in memory. It renders as REDACTED under fmt, slog and JSON, and
// fmt prints an address instead of it even when nested in an unexported field. The zero value is
// no secret.
type Secret struct {
	v *string
}

// NewSecret wraps a plaintext client secret; the empty string gives the zero Secret.
func NewSecret(plaintext string) Secret {
	if plaintext == "" {
		return Secret{}
	}
	return Secret{v: &plaintext}
}

// Reveal returns the plaintext, for the token exchange and the sealing store only; never log or
// return it.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

func (s Secret) IsZero() bool { return s.v == nil || *s.v == "" }

// String renders s redacted.
func (s Secret) String() string { return "REDACTED" }

// GoString renders s for %#v redacted.
func (s Secret) GoString() string { return "federation.Secret{REDACTED}" }

// LogValue renders s for slog redacted.
func (s Secret) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// MarshalJSON renders s redacted, so a marshalled configuration never carries the secret.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"REDACTED"`), nil }

// Provider is the value spec of one identity provider. Issuer and JWKSURL are pinned by the spec:
// the expected issuer of an id_token or RFC 9207 response is Issuer, never the origin of AuthURL. A
// Provider is a plain value: copy it freely, but treat its slices as read-only. Adjust it after a
// constructor, then rely on Validate or Complete.
type Provider struct {
	Name              string
	ClientID          string
	ClientSecret      Secret
	AuthURL           string
	TokenURL          string
	UserInfoURL       string
	Scopes            []string
	Issuer            string
	JWKSURL           string
	Domains           []string
	EmailVerification EmailVerification
}

// String redacts the client secret.
func (p Provider) String() string {
	return "federation.Provider{" + p.Name + "}"
}

// GoString redacts the client secret.
func (p Provider) GoString() string { return p.String() }

// LogValue logs the provider by name only.
func (p Provider) LogValue() slog.Value { return slog.StringValue(p.Name) }

// Validate checks the structure of p. Endpoints and JWKS may still be empty when an issuer is set
// and awaits discovery; use Complete once discovery ran. The issuer carries no query or fragment
// (OIDC Core §2). It joins ErrInvalidProvider into every failure.
func (p Provider) Validate() error {
	if !namePattern.MatchString(p.Name) {
		return invalid("name must match " + namePattern.String())
	}
	if p.ClientID == "" {
		return invalid("client id is empty")
	}
	if !p.EmailVerification.Valid() {
		return invalid("email verification is not a declared value")
	}
	for field, raw := range map[string]string{
		"auth url": p.AuthURL, "token url": p.TokenURL, "userinfo url": p.UserInfoURL, "jwks url": p.JWKSURL,
	} {
		if raw == "" {
			continue
		}
		if err := checkHTTPS(raw); err != nil {
			return invalid(field + ": " + err.Error())
		}
	}
	if p.Issuer != "" {
		if err := checkIssuer(p.Issuer); err != nil {
			return err
		}
	}
	if p.JWKSURL != "" && p.Issuer == "" {
		return invalid("jwks url without an issuer")
	}
	for _, d := range p.Domains {
		if !domainPattern.MatchString(d) {
			return invalid("domain " + d + " is not a lowercase hostname")
		}
	}
	return nil
}

// Complete is Validate plus the endpoints a login needs: AuthURL, TokenURL, and either UserInfoURL
// or a pinned Issuer with JWKSURL. A generic OIDC spec is complete only after discovery.
func (p Provider) Complete() error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.AuthURL == "" || p.TokenURL == "" {
		return invalid("auth url or token url is empty")
	}
	if p.UserInfoURL == "" && (p.Issuer == "" || p.JWKSURL == "") {
		return invalid("neither a userinfo url nor an issuer with a jwks url")
	}
	return nil
}

// NeedsDiscovery reports whether p pins an issuer but lacks endpoints or JWKS to be resolved.
func (p Provider) NeedsDiscovery() bool {
	return p.Issuer != "" && (p.AuthURL == "" || p.TokenURL == "" || p.JWKSURL == "")
}

// Verified reports whether the provider's email may be treated as verified. claim is the
// provider's email_verified claim; a false claim is never upgraded, whatever EmailVerification
// says. Never refuses; ClaimBased needs an email whose domain is exactly one of Domains; Always
// accepts any domain. email must be a single addr-spec with one '@', no whitespace or control
// character, and an ASCII hostname domain.
func (p Provider) Verified(email string, claim bool) bool {
	if !claim {
		return false
	}
	domain, ok := emailDomain(email)
	if !ok {
		return false
	}
	switch p.EmailVerification {
	case Always:
		return true
	case ClaimBased:
		for _, d := range p.Domains {
			if d == domain {
				return true
			}
		}
	}
	return false
}

func checkIssuer(issuer string) error {
	if strings.ContainsAny(issuer, "?#") {
		return invalid("issuer: query or fragment in url")
	}
	if err := checkHTTPS(issuer); err != nil {
		return invalid("issuer: " + err.Error())
	}
	return nil
}

// ForRuntime returns p as it may be registered at runtime by the caller. The email verification is
// capped at ClaimBased, and downgraded to Never when no Domains are set. Domains are normalised to
// lowercase and may be set only by a system caller; any other caller gets ErrDomainsSystemOnly.
// The returned spec is validated.
func ForRuntime(p Provider, by principal.Caller) (Provider, error) {
	if by.Kind() == 0 {
		return Provider{}, invalid("zero caller")
	}
	if len(p.Domains) > 0 && by.Kind() != principal.CallerSystem {
		return Provider{}, errors.Join(ErrInvalidProvider, ErrDomainsSystemOnly)
	}
	return capRuntime(p)
}

// FromStore rebuilds the Provider of a spec loaded from the federation store, secret being its
// opened client secret. Every stored spec was registered at runtime, so the runtime cap of
// ForRuntime is applied again: a persisted Always row is honoured as ClaimBased only. The returned
// spec is validated.
func FromStore(spec storefed.ProviderSpec, secret Secret) (Provider, error) {
	return capRuntime(Provider{
		Name:              spec.Name,
		ClientID:          spec.ClientID,
		ClientSecret:      secret,
		AuthURL:           spec.AuthURL,
		TokenURL:          spec.TokenURL,
		UserInfoURL:       spec.UserInfoURL,
		Scopes:            append([]string(nil), spec.Scopes...),
		Issuer:            spec.Issuer,
		JWKSURL:           spec.JWKSURL,
		Domains:           spec.Domains,
		EmailVerification: spec.EmailVerification,
	})
}

func capRuntime(p Provider) (Provider, error) {
	out := p
	out.Domains = normalizeDomains(p.Domains)
	if out.EmailVerification == Always {
		out.EmailVerification = ClaimBased
	}
	if out.EmailVerification == ClaimBased && len(out.Domains) == 0 {
		out.EmailVerification = Never
	}
	if err := out.Validate(); err != nil {
		return Provider{}, err
	}
	return out, nil
}

func normalizeDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func emailDomain(email string) (string, bool) {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return "", false
	}
	for _, r := range email {
		if r <= ' ' || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", false
		}
	}
	domain = strings.ToLower(domain)
	if !domainPattern.MatchString(domain) {
		return "", false
	}
	return domain, true
}

func invalid(msg string) error {
	return errors.Join(ErrInvalidProvider, errors.New(msg))
}

func checkHTTPS(raw string) error {
	if strings.Contains(raw, "#") {
		return errors.New("fragment in url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "https":
		return errors.New("scheme must be https")
	case u.Hostname() == "":
		return errors.New("host is empty")
	case u.User != nil:
		return errors.New("credentials in url")
	}
	return nil
}
