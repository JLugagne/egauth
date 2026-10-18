package federation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	storefed "github.com/JLugagne/egauth/store/federation"
)

const secretValue = "s3cr3t-value"

func valid() federation.Provider {
	return federation.Provider{
		Name: "acme", ClientID: "id", ClientSecret: federation.NewSecret(secretValue),
		AuthURL: "https://idp.example.com/a", TokenURL: "https://idp.example.com/t",
		Issuer: "https://idp.example.com", JWKSURL: "https://idp.example.com/k",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*federation.Provider)
		ok     bool
	}{
		{"valid", func(*federation.Provider) {}, true},
		{"empty name", func(p *federation.Provider) { p.Name = "" }, false},
		{"upper name", func(p *federation.Provider) { p.Name = "Acme" }, false},
		{"empty client id", func(p *federation.Provider) { p.ClientID = "" }, false},
		{"undeclared verification", func(p *federation.Provider) { p.EmailVerification = 7 }, false},
		{"http issuer", func(p *federation.Provider) { p.Issuer = "http://idp.example.com" }, false},
		{"credentials in url", func(p *federation.Provider) { p.AuthURL = "https://u:p@idp.example.com/a" }, false},
		{"jwks without issuer", func(p *federation.Provider) { p.Issuer = "" }, false},
		{"claim based without domains trusts nothing", func(p *federation.Provider) { p.EmailVerification = federation.ClaimBased }, true},
		{"issuer with query", func(p *federation.Provider) { p.Issuer = "https://idp.example.com?x=1" }, false},
		{"issuer with empty query", func(p *federation.Provider) { p.Issuer = "https://idp.example.com/?" }, false},
		{"issuer with empty fragment", func(p *federation.Provider) { p.Issuer = "https://idp.example.com/#" }, false},
		{"auth url with empty fragment", func(p *federation.Provider) { p.AuthURL = "https://idp.example.com/a#" }, false},
		{"userinfo url with query", func(p *federation.Provider) { p.UserInfoURL = "https://idp.example.com/u?fields=email" }, true},
		{"claim based with domains", func(p *federation.Provider) {
			p.EmailVerification = federation.ClaimBased
			p.Domains = []string{"example.com"}
		}, true},
		{"bad domain", func(p *federation.Provider) { p.Domains = []string{"Example.com/x"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid()
			tt.mutate(&p)
			err := p.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, federation.ErrInvalidProvider) {
				t.Fatalf("error must wrap ErrInvalidProvider: %v", err)
			}
		})
	}
}

func TestCompleteAndDiscovery(t *testing.T) {
	p := valid()
	if err := p.Complete(); err != nil {
		t.Fatal(err)
	}
	if p.NeedsDiscovery() {
		t.Fatal("a pinned spec needs no discovery")
	}
	bare := federation.Provider{Name: "oidc", ClientID: "id", Issuer: "https://idp.example.com"}
	if err := bare.Validate(); err != nil {
		t.Fatal(err)
	}
	if bare.Complete() == nil || !bare.NeedsDiscovery() {
		t.Fatal("an issuer-only spec awaits discovery")
	}
}

func TestVerified(t *testing.T) {
	claim := valid()
	claim.EmailVerification = federation.ClaimBased
	claim.Domains = []string{"example.com"}
	claimNoDomains := valid()
	claimNoDomains.EmailVerification = federation.ClaimBased
	always := valid()
	always.EmailVerification = federation.Always
	never := valid()
	tests := []struct {
		name  string
		p     federation.Provider
		email string
		claim bool
		want  bool
	}{
		{"never", never, "a@example.com", true, false},
		{"always claimed", always, "a@anything.org", true, true},
		{"always false claim is not upgraded", always, "victim@corp.example", false, false},
		{"always malformed", always, "no-at-sign", true, false},
		{"always empty local", always, "@example.com", true, false},
		{"always empty domain", always, "a@", true, false},
		{"always embedded at", always, "a@evil.com@example.com", true, false},
		{"always control char", always, "a\x00b@example.com", true, false},
		{"always del char", always, "a\x7f@example.com", true, false},
		{"always line separator", always, "a\u2028@example.com", true, false},
		{"always display name", always, "Eve <a@example.com>", true, false},
		{"claim listed", claim, "a@example.com", true, true},
		{"claim listed uppercase", claim, "a@EXAMPLE.com", true, true},
		{"claim false", claim, "a@example.com", false, false},
		{"claim other domain", claim, "a@evil.com", true, false},
		{"claim subdomain", claim, "a@sub.example.com", true, false},
		{"claim suffix trick", claim, "a@example.com.evil.com", true, false},
		{"claim embedded at", claim, "a@evil.com@example.com", true, false},
		{"claim without domains", claimNoDomains, "a@example.com", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Verified(tt.email, tt.claim); got != tt.want {
				t.Fatalf("Verified(%q, %v) = %v, want %v", tt.email, tt.claim, got, tt.want)
			}
		})
	}
}

func TestForRuntime(t *testing.T) {
	session, err := core.SessionCaller(principaltest.Full(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	system, err := core.SystemCaller(principaltest.Full().Subject().Tenant, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}

	always := valid()
	always.EmailVerification = federation.Always

	got, err := federation.ForRuntime(always, session)
	if err != nil || got.EmailVerification != federation.Never {
		t.Fatalf("Always without domains must fall to Never, got %v %v", got.EmailVerification, err)
	}

	claim := valid()
	claim.EmailVerification = federation.ClaimBased
	claim.Domains = []string{"Example.com", "example.com"}
	if _, err := federation.ForRuntime(claim, session); !errors.Is(err, federation.ErrDomainsSystemOnly) || !errors.Is(err, federation.ErrInvalidProvider) {
		t.Fatalf("session caller setting domains: %v", err)
	}
	got, err = federation.ForRuntime(claim, system)
	if err != nil {
		t.Fatal(err)
	}
	if got.EmailVerification != federation.ClaimBased || len(got.Domains) != 1 || got.Domains[0] != "example.com" {
		t.Fatalf("unexpected runtime spec %+v", got)
	}

	if _, err := federation.ForRuntime(valid(), core.Caller{}); err == nil {
		t.Fatal("the zero caller must be refused")
	}
}

func TestFromStoreReappliesTheRuntimeCap(t *testing.T) {
	base := valid()
	row := storefed.ProviderSpec{
		Name: base.Name, ClientID: base.ClientID, AuthURL: base.AuthURL, TokenURL: base.TokenURL,
		Issuer: base.Issuer, JWKSURL: base.JWKSURL, EmailVerification: federation.Always,
	}
	got, err := federation.FromStore(row, base.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got.EmailVerification != federation.Never || got.Verified("a@example.com", true) {
		t.Fatalf("a stored Always row without domains must trust nothing, got %v", got.EmailVerification)
	}
	if got.ClientSecret.Reveal() != secretValue {
		t.Fatal("the opened secret must be carried")
	}

	row.Domains = []string{"Example.com"}
	got, err = federation.FromStore(row, base.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got.EmailVerification != federation.ClaimBased || !got.Verified("a@example.com", true) || got.Verified("a@other.com", true) {
		t.Fatalf("a stored Always row must be capped at ClaimBased, got %v %v", got.EmailVerification, got.Domains)
	}

	row.Issuer = "http://idp.example.com"
	if _, err := federation.FromStore(row, base.ClientSecret); !errors.Is(err, federation.ErrInvalidProvider) {
		t.Fatalf("a stored row is validated, got %v", err)
	}
}

func TestSecretIsNeverFormatted(t *testing.T) {
	p := valid()
	type unexported struct{ p federation.Provider }
	type config struct{ Providers []federation.Provider }
	jsonOut, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	cfgOut, err := json.Marshal(config{Providers: []federation.Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	var slogOut bytes.Buffer
	slog.New(slog.NewJSONHandler(&slogOut, nil)).Info("cfg", "oauth", config{Providers: []federation.Provider{p}})
	var slogText bytes.Buffer
	slog.New(slog.NewTextHandler(&slogText, nil)).Info("cfg", "oauth", unexported{p})
	for _, s := range []string{
		fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), p.String(), p.LogValue().String(),
		slog.AnyValue(p).Resolve().String(),
		fmt.Sprintf("%+v", unexported{p}), fmt.Sprintf("%#v", unexported{p}), fmt.Sprintf("%v", []any{unexported{p}}),
		fmt.Sprintf("%v", p.ClientSecret), fmt.Sprintf("%#v", p.ClientSecret),
		string(jsonOut), string(cfgOut), slogOut.String(), slogText.String(),
	} {
		if strings.Contains(s, secretValue) {
			t.Fatalf("secret leaked in %q", s)
		}
	}
	if p.ClientSecret.Reveal() != secretValue || federation.NewSecret("").Reveal() != "" || !federation.NewSecret("").IsZero() {
		t.Fatal("Reveal must return the plaintext")
	}
}

func TestValidateNamesTheSameURLEveryTime(t *testing.T) {
	p := valid()
	p.AuthURL = "http://idp.example.com/a"
	p.TokenURL = "http://idp.example.com/t"
	p.UserInfoURL = "http://idp.example.com/u"
	first := p.Validate().Error()
	for range 50 {
		if got := p.Validate().Error(); got != first {
			t.Fatalf("Validate reported %q then %q for the same provider", first, got)
		}
	}
}
