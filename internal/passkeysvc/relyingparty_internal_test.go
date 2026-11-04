package passkeysvc

import (
	"slices"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/store/ceremony"
)

func TestSessionPayloadLengthIgnoresTheExpiryNanoseconds(t *testing.T) {
	base := time.Date(2026, 10, 17, 0, 47, 12, 0, time.FixedZone("CEST", 2*3600))
	var lengths []int
	for _, ns := range []int{124833068, 45027600, 100000000, 0} {
		sd := &webauthn.SessionData{
			Challenge:      "bhYWEXVJsCAMdHrHkCtT_Kx0q4kzxVUOE1ZHN3RHq7I",
			RelyingPartyID: "auth.example.com",
			UserID:         make([]byte, 16),
			Expires:        base.Add(time.Duration(ns)),
		}
		p, err := sessionPayload(sd)
		if err != nil {
			t.Fatal(err)
		}
		lengths = append(lengths, len(p.Session))
	}
	for _, n := range lengths[1:] {
		if n != lengths[0] {
			t.Fatalf("the sealed session length follows the expiry's nanoseconds, so the ceremony handle length jitters: %v", lengths)
		}
	}
}

func TestSessionPayloadKeepsTheExpiryWithinASecond(t *testing.T) {
	exp := time.Now().Add(5 * time.Minute)
	p, err := sessionPayload(&webauthn.SessionData{Challenge: "c", Expires: exp})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := sessionOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Expires.After(exp) || exp.Sub(sd.Expires) >= time.Second {
		t.Fatalf("expiry %v moved from %v by more than the truncation", sd.Expires, exp)
	}
}

func TestRelyingPartyIDDefaultsToTheFirstOriginHost(t *testing.T) {
	o, err := csrf.NewOrigins("https://auth.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := (&Service{origins: o, displayName: "Example"}).relyingParty(core.TenantID{}, ceremony.PasskeyRegistration)
	if err != nil {
		t.Fatal(err)
	}
	if rp.Config.RPID != "auth.example.com" {
		t.Fatalf("RPID %q", rp.Config.RPID)
	}
}

func TestRelyingPartyIDOverrideCoversTheSPAOrigins(t *testing.T) {
	o, err := csrf.NewOrigins("https://auth.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if o, err = o.WithSameSite([]string{"https://app.example.com"}); err != nil {
		t.Fatal(err)
	}
	rp, err := (&Service{origins: o, rpID: "example.com", displayName: "Example"}).relyingParty(core.TenantID{}, ceremony.PasskeyRegistration)
	if err != nil {
		t.Fatal(err)
	}
	if rp.Config.RPID != "example.com" {
		t.Fatalf("RPID %q", rp.Config.RPID)
	}
	if !slices.Contains(rp.Config.RPOrigins, "https://app.example.com") || !slices.Contains(rp.Config.RPOrigins, "https://auth.example.com") {
		t.Fatalf("RPOrigins %v", rp.Config.RPOrigins)
	}
}
