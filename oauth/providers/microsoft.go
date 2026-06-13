package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JLugagne/egauth/oauth"
)

// Microsoft (Entra ID / Azure AD) endpoints. The authorization and token endpoints are
// tenant-scoped; the userinfo endpoint is the tenant-independent Microsoft Graph OIDC
// endpoint.
const (
	microsoftAuthURLFmt  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	microsoftTokenURLFmt = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	microsoftUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"

	// MicrosoftIssuerFmt and MicrosoftJWKSURLFmt are Entra ID's per-tenant OIDC issuer and JWKS
	// endpoint templates. Format them with the same tenant value passed to Microsoft and hand
	// the result to oauth.WithOIDC for id_token validation. Note: for the multi-tenant "common"
	// and "organizations" tenants the id_token issuer contains the caller's home tenant GUID
	// rather than the literal "common", so issuer validation must account for that — prefer a
	// single-tenant value (your directory GUID or verified domain) when you can.
	MicrosoftIssuerFmt  = "https://login.microsoftonline.com/%s/v2.0"
	MicrosoftJWKSURLFmt = "https://login.microsoftonline.com/%s/discovery/v2.0/keys"

	// MicrosoftTenantCommon accepts both work/school (Entra ID) and personal Microsoft accounts.
	// MicrosoftTenantOrganizations restricts to work/school accounts; MicrosoftTenantConsumers
	// to personal accounts. You may also pass a directory (tenant) GUID or a verified domain.
	MicrosoftTenantCommon        = "common"
	MicrosoftTenantOrganizations = "organizations"
	MicrosoftTenantConsumers     = "consumers"
)

// Microsoft builds a Provider for Microsoft (Entra ID / Azure AD) sign-in. The tenant selects
// the audience: pass MicrosoftTenantCommon (personal + work/school), one of the other tenant
// constants, or a specific directory GUID / verified domain. Default scopes request the OpenID
// identity, email and basic profile.
//
// By default the user is resolved via the Microsoft Graph userinfo endpoint. For id_token
// validation, derive the issuer and JWKS URL from the same tenant and pass oauth.WithOIDC:
//
//	tenant := providers.MicrosoftTenantOrganizations
//	providers.Microsoft(tenant, id, secret, oauth.WithOIDC(oauth.OIDCConfig{
//	    Issuer:  fmt.Sprintf(providers.MicrosoftIssuerFmt, tenant),
//	    JWKSURL: fmt.Sprintf(providers.MicrosoftJWKSURLFmt, tenant),
//	}))
func Microsoft(tenant, clientID, clientSecret string, opts ...oauth.ProviderOption) *oauth.Provider {
	if tenant == "" {
		tenant = MicrosoftTenantCommon
	}
	authURL := fmt.Sprintf(microsoftAuthURLFmt, tenant)
	tokenURL := fmt.Sprintf(microsoftTokenURLFmt, tenant)
	return oauth.New("microsoft", clientID, clientSecret, authURL, tokenURL,
		[]string{"openid", "email", "profile"}, fetchMicrosoftUser, opts...)
}

func fetchMicrosoftUser(ctx context.Context, c *http.Client, accessToken string) (*oauth.UserInfo, error) {
	var u struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := oauth.GetJSON(ctx, c, microsoftUserInfoURL, accessToken, &u); err != nil {
		return nil, err
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("%w: provider returned no subject id", oauth.ErrUserInfoFailed)
	}
	// The Graph userinfo endpoint does not return an email_verified claim, so it is left false;
	// callers who need a verified signal should enable oauth.WithOIDC and read the id_token.
	return &oauth.UserInfo{
		ProviderID: u.Sub,
		Email:      u.Email,
		Name:       u.Name,
	}, nil
}
