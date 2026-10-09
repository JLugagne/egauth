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
