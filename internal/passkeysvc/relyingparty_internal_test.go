package passkeysvc

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
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
