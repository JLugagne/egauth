package pgx

import (
	"context"
	"errors"
	"testing"
)

// TestIssuerAllowlist covers the opt-in operator issuer allowlist (SEC-07 dynamic-store
// hardening). It exercises the pure gate plus UpsertProvider's pre-DB rejection, which needs no
// database connection because an off-allowlist issuer is refused before any pool access.
func TestIssuerAllowlist(t *testing.T) {
	t.Run("no allowlist allows everything", func(t *testing.T) {
		s := NewStore(nil)
		if err := s.checkIssuerAllowed("https://anything.example.com"); err != nil {
			t.Fatalf("empty allowlist must allow all issuers, got %v", err)
		}
		if err := s.checkIssuerAllowed(""); err != nil {
			t.Fatalf("empty allowlist must allow even empty issuer, got %v", err)
		}
	})

	t.Run("empty slice keeps allowlist off", func(t *testing.T) {
		s := NewStore(nil, WithIssuerAllowlist(nil))
		if err := s.checkIssuerAllowed("https://anything.example.com"); err != nil {
			t.Fatalf("nil allowlist must allow all issuers, got %v", err)
		}
		s2 := NewStore(nil, WithIssuerAllowlist([]string{}))
		if err := s2.checkIssuerAllowed("https://anything.example.com"); err != nil {
			t.Fatalf("empty allowlist must allow all issuers, got %v", err)
		}
	})

	t.Run("on-allowlist issuer allowed", func(t *testing.T) {
		s := NewStore(nil, WithIssuerAllowlist([]string{"https://idp-a.example.com", "https://idp-b.example.com"}))
		if err := s.checkIssuerAllowed("https://idp-b.example.com"); err != nil {
			t.Fatalf("on-allowlist issuer must be allowed, got %v", err)
		}
	})

	t.Run("off-allowlist issuer rejected", func(t *testing.T) {
		s := NewStore(nil, WithIssuerAllowlist([]string{"https://idp-a.example.com"}))
		err := s.checkIssuerAllowed("https://evil.example.net")
		if !errors.Is(err, ErrIssuerNotAllowed) {
			t.Fatalf("off-allowlist issuer must be rejected with ErrIssuerNotAllowed, got %v", err)
		}
	})

	t.Run("UpsertProvider rejects off-allowlist issuer before touching the DB", func(t *testing.T) {
		s := NewStore(nil, WithIssuerAllowlist([]string{"https://idp-a.example.com"}))
		// db is nil; if the allowlist did not short-circuit, this would panic on s.db.Exec.
		err := s.UpsertProvider(context.Background(), "tenant", "sso", OIDCProviderConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			AuthURL:      "https://evil.example.net/auth",
			TokenURL:     "https://evil.example.net/token",
			Issuer:       "https://evil.example.net",
			JWKSURL:      "https://evil.example.net/jwks",
		})
		if !errors.Is(err, ErrIssuerNotAllowed) {
			t.Fatalf("UpsertProvider must reject off-allowlist issuer, got %v", err)
		}
	})
}
