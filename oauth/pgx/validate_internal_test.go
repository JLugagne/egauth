package pgx

import (
	"context"
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

// TestValidateProviderConfig covers PANIC-01: the pure config validator that GetProvider runs
// per request before building the Provider. An empty client_id or empty issuer would otherwise
// reach oauth.WithOIDC, which used to panic during the request. The validator now rejects them
// up front with ErrInvalidProviderConfig, and UpsertProvider runs the same check so a bad row
// can never be stored in the first place.
func TestValidateProviderConfig(t *testing.T) {
	valid := OIDCProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
	}
	if err := validateProviderConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(c *OIDCProviderConfig)
		field  string
	}{
		{"empty client_id", func(c *OIDCProviderConfig) { c.ClientID = "" }, "client_id"},
		{"blank client_id", func(c *OIDCProviderConfig) { c.ClientID = "   " }, "client_id"},
		{"empty issuer", func(c *OIDCProviderConfig) { c.Issuer = "" }, "issuer"},
		{"blank issuer", func(c *OIDCProviderConfig) { c.Issuer = "  " }, "issuer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			err := validateProviderConfig(c)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !errors.Is(err, ErrInvalidProviderConfig) {
				t.Fatalf("error = %v, want wrapped ErrInvalidProviderConfig", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q should name the offending field %q", err.Error(), tc.field)
			}
		})
	}
}

// TestUpsertProviderRejectsEmptyClientID verifies UpsertProvider refuses a registration with an
// empty client_id before any DB access (pool is nil; reaching s.pool.Exec would panic). This
// stops a row that would later panic at resolution from being stored (PANIC-01).
func TestUpsertProviderRejectsEmptyClientID(t *testing.T) {
	s := NewStore(nil)
	err := s.UpsertProvider(context.Background(), "tenant", "sso", OIDCProviderConfig{
		ClientID:     "",
		ClientSecret: "secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		JWKSURL:      "https://sso.example.com/jwks",
	})
	if !errors.Is(err, ErrInvalidProviderConfig) {
		t.Fatalf("UpsertProvider must reject empty client_id with ErrInvalidProviderConfig, got %v", err)
	}
}
