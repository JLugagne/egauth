package federationsvc

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/outbound"
)

var (
	// ErrDiscovery is returned by Discover when the discovery document cannot be fetched or read.
	ErrDiscovery = errors.New("federationsvc: OIDC discovery failed")
	// ErrIssuerNotPinned is returned by Discover when the document names another issuer than the
	// spec's: the spec Issuer is the trust anchor and is never replaced by a discovered one.
	ErrIssuerNotPinned = errors.New("federationsvc: discovered issuer differs from the spec issuer")
)

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Discover resolves p through OpenID Connect Discovery over c, which must be the outbound scope of
// the spec (Static for configured providers, Tenant for runtime ones). The document must name
// exactly p.Issuer; it only fills endpoints p leaves empty, never overriding one the spec sets. A
// spec without Issuer is returned unchanged. The result is checked with federation.Provider.Complete.
// It returns ErrDiscovery, ErrIssuerNotPinned or the error of Complete.
func Discover(ctx context.Context, c *outbound.Client, p federation.Provider) (federation.Provider, error) {
	if c == nil {
		return federation.Provider{}, errors.Join(ErrDiscovery, outbound.ErrZeroClient)
	}
	return discover(ctx, c, p)
}

func discover(ctx context.Context, d doer, p federation.Provider) (federation.Provider, error) {
	if err := p.Validate(); err != nil {
		return federation.Provider{}, err
	}
	if p.Issuer == "" {
		return p, p.Complete()
	}
	var doc discoveryDocument
	if err := getJSON(ctx, d, strings.TrimSuffix(p.Issuer, "/")+"/.well-known/openid-configuration", "", &doc); err != nil {
		return federation.Provider{}, errors.Join(ErrDiscovery, err)
	}
	if doc.Issuer != p.Issuer {
		return federation.Provider{}, ErrIssuerNotPinned
	}
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&p.AuthURL, doc.AuthorizationEndpoint)
	fill(&p.TokenURL, doc.TokenEndpoint)
	fill(&p.UserInfoURL, doc.UserinfoEndpoint)
	fill(&p.JWKSURL, doc.JWKSURI)
	if p.JWKSURL == "" {
		return federation.Provider{}, errors.Join(ErrDiscovery, errors.New("no jwks_uri"))
	}
	return p, p.Complete()
}

func getJSON(ctx context.Context, d doer, rawURL, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := d.Do(req)
	if err != nil {
		return err
	}
	return decodeJSON(resp, out)
}
