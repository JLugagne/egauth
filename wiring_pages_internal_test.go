package egauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildPagesKeepsAbsolutePublicOriginLandingPagesAsPaths(t *testing.T) {
	cfg := &Config[struct{}]{PublicOrigin: "https://app.example.com", ExtraOrigins: []string{"https://admin.example.com"}}
	cfg.Pages = Pages{
		Login:      "https://app.example.com/login",
		AfterLogin: "https://app.example.com/home?x=1",
		MFA:        "https://app.example.com",
		Reauth:     "/reauth",
	}
	v := &problems{}
	pages, login := buildPages(cfg, v)
	require.NoError(t, v.err())
	require.Equal(t, "/home?x=1", pages.AfterLogin)
	require.Equal(t, "/", pages.MFA)
	require.Equal(t, "/reauth", pages.Reauth)
	require.Equal(t, "https://app.example.com/login", login.String())
}

func TestBuildPagesReportsWhatItCannotServe(t *testing.T) {
	cfg := &Config[struct{}]{PublicOrigin: "https://app.example.com", ExtraOrigins: []string{"https://admin.example.com"}}
	cfg.Pages = Pages{
		Login:      "https://evil.example.net/login",
		AfterLogin: "https://admin.example.com/home",
		MFA:        "https://app.example.com:8443/mfa",
		Reauth:     "https://evil.example.net/reauth",
	}
	v := &problems{}
	_, _ = buildPages(cfg, v)
	for _, f := range []string{"Pages.Login", "Pages.AfterLogin", "Pages.MFA", "Pages.Reauth"} {
		require.Contains(t, v.err().Error(), f)
	}
}

func TestBuildPagesKeepsAnAbsoluteLoginOnTheTenantHostUnderSubdomainTenancy(t *testing.T) {
	cfg := &Config[struct{}]{PublicOrigin: "https://{tenant}.example.com", Tenancy: TenantBySubdomain()}
	cfg.Pages = Pages{Login: "https://{tenant}.example.com/login"}
	v := &problems{}
	_, login := buildPages(cfg, v)
	require.NoError(t, v.err())
	require.Equal(t, "/login", login.String(), "an absolute login must not be frozen at the sample tenant")
}
