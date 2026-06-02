package pgx

import (
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/oauth"
)

func TestValidateProviderURLs(t *testing.T) {
	valid := OIDCProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
	}
	if err := validateProviderURLs(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(c *OIDCProviderConfig)
		field  string
	}{
		{"loopback token_url", func(c *OIDCProviderConfig) { c.TokenURL = "https://127.0.0.1/token" }, "token_url"},
		{"http token_url", func(c *OIDCProviderConfig) { c.TokenURL = "http://sso.example.com/token" }, "token_url"},
		{"metadata jwks_url", func(c *OIDCProviderConfig) { c.JWKSURL = "https://169.254.169.254/jwks" }, "jwks_url"},
		{"http jwks_url", func(c *OIDCProviderConfig) { c.JWKSURL = "http://sso.example.com/jwks" }, "jwks_url"},
		{"rfc1918 auth_url", func(c *OIDCProviderConfig) { c.AuthURL = "https://10.0.0.1/auth" }, "auth_url"},
		{"http issuer", func(c *OIDCProviderConfig) { c.Issuer = "http://sso.example.com" }, "issuer"},
		{"empty token_url", func(c *OIDCProviderConfig) { c.TokenURL = "" }, "token_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			err := validateProviderURLs(c)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !errors.Is(err, oauth.ErrBlockedURL) {
				t.Fatalf("error = %v, want wrapped oauth.ErrBlockedURL", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q should name the offending field %q", err.Error(), tc.field)
			}
		})
	}
}
