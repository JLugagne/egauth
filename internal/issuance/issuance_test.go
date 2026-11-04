package issuance_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/issuance"
)

var _ httpx.Issuer = (*issuance.Issuer)(nil)

var _ httpx.EnrollmentReader = (*issuance.Enrollment)(nil)

func TestNewReportsEveryMissingMember(t *testing.T) {
	_, err := issuance.New(issuance.Config{})
	if !errors.Is(err, issuance.ErrInvalidConfig) {
		t.Fatalf("New(zero) = %v", err)
	}
	for _, name := range []string{"Accounts", "Enrollment", "Backend", "Claims", "Flows", "Completer", "Cookies", "Origins", "RememberMe", "Audit"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %s: %v", name, err)
		}
	}
}

// TestNewRefusesMalformedPages pins G4 for the pages: a page is validated once at construction, so
// no login can fail on it later.
func TestNewRefusesMalformedPages(t *testing.T) {
	for name, pages := range map[string]issuance.Pages{
		"AfterLogin": {AfterLogin: "//evil.example/home"},
		"MFA":        {MFA: "https://evil.example/mfa"},
		"Reauth":     {Reauth: "reauth"},
	} {
		_, err := issuance.New(issuance.Config{Pages: pages})
		if !errors.Is(err, issuance.ErrInvalidConfig) || !strings.Contains(err.Error(), "Pages."+name) {
			t.Errorf("Pages.%s accepted or not named: %v", name, err)
		}
	}
	_, err := issuance.New(issuance.Config{Pages: issuance.Pages{AfterLogin: "/", MFA: "/mfa?step=2", Reauth: "/reauth"}})
	if strings.Contains(err.Error(), "Pages") {
		t.Fatalf("valid pages refused: %v", err)
	}
}

// TestNewAcceptsPagesOnSPAOrigins: a page may be an absolute URL on a declared single-page
// application origin, and only there.
func TestNewAcceptsPagesOnSPAOrigins(t *testing.T) {
	spa := []string{"https://spa.example.com"}
	_, err := issuance.New(issuance.Config{Pages: issuance.Pages{
		AfterLogin: "https://spa.example.com/home", MFA: "https://spa.example.com/mfa?step=2", Reauth: "/reauth", SPAOrigins: spa,
	}})
	if strings.Contains(err.Error(), "Pages") {
		t.Fatalf("pages on a SPA origin refused: %v", err)
	}
	_, err = issuance.New(issuance.Config{Pages: issuance.Pages{AfterLogin: "https://evil.example/home", SPAOrigins: spa}})
	if !errors.Is(err, issuance.ErrInvalidConfig) || !strings.Contains(err.Error(), "Pages.AfterLogin") {
		t.Fatalf("a page outside the SPA origins accepted: %v", err)
	}
}
