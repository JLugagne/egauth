package issuance_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/store/mfa"
	mfamem "github.com/JLugagne/egauth/store/mfa/memory"
	"github.com/JLugagne/egauth/store/passkey"
	passkeymem "github.com/JLugagne/egauth/store/passkey/memory"
)

var goldenNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type goldenStores struct {
	mfa      *mfamem.Store
	passkeys *passkeymem.Store
}

func (g goldenStores) confirmTOTP(t *testing.T, s core.Subject, codes ...string) {
	t.Helper()
	ctx := context.Background()
	e := mfa.Enrollment{Subject: s, Sealed: []byte("sealed-secret"), AADVersion: mfa.AADVersionCurrent, CreatedAt: goldenNow}
	if err := g.mfa.SaveTOTP(ctx, e); err != nil {
		t.Fatal(err)
	}
	at := goldenNow
	e.ConfirmedAt = &at
	if err := g.mfa.ConfirmEnrollment(ctx, e, codes); err != nil {
		t.Fatal(err)
	}
}

func (g goldenStores) addPasskey(t *testing.T, s core.Subject, id string) {
	t.Helper()
	err := g.passkeys.Save(context.Background(), passkey.Credential{
		Subject: s, ID: passkey.CredentialID(id), PublicKey: []byte{1, 2, 3}, CreatedAt: goldenNow,
		Discoverable: passkey.Confirmed,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func goldenAdmit(t *testing.T, s core.Subject, d core.MFADecision, v core.Verified) bool {
	t.Helper()
	p, err := core.NewPending(s.Tenant, core.RememberDeclined, redirect.Target{}, core.TransportCookies, core.RememberUserChoice, goldenNow)
	if err != nil {
		t.Fatal(err)
	}
	st := core.NewAccountState(true, false, false, false, true, 0)
	if p, err = p.Add(v, st); err != nil {
		t.Fatal(err)
	}
	adm, err := core.Admit(p, st, d, goldenNow)
	if err != nil {
		t.Fatal(err)
	}
	_, ok := adm.Session()
	return ok
}

// TestEnrolledGolden pins the enrollment decision of DESIGN §5.2 (D1, C-01, C-45, C-71): the
// decision reads only the confirmed TOTP and the active passkeys, recovery codes never raise or
// satisfy the floor on their own, and a passkey-only user logging in with the passkey is admitted.
func TestEnrolledGolden(t *testing.T) {
	type row struct {
		name     string
		setup    func(t *testing.T, g goldenStores, s core.Subject)
		required bool
		factors  []core.Factor
		primary  func(t *testing.T, s core.Subject) core.Verified
		admitted bool
	}
	password := func(t *testing.T, s core.Subject) core.Verified {
		t.Helper()
		v, err := factors.Password(s, goldenNow)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rows := []row{
		{
			name:     "none",
			setup:    func(*testing.T, goldenStores, core.Subject) {},
			required: false,
			primary:  password,
			admitted: true,
		},
		{
			name: "totp",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				g.confirmTOTP(t, s, "h1", "h2")
			},
			required: true,
			factors:  []core.Factor{core.FactorRecoveryCode, core.FactorTOTP},
			primary:  password,
			admitted: false,
		},
		{
			name: "unconfirmed totp",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				err := g.mfa.SaveTOTP(context.Background(), mfa.Enrollment{
					Subject: s, Sealed: []byte("sealed-secret"), AADVersion: mfa.AADVersionCurrent, CreatedAt: goldenNow,
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			required: false,
			primary:  password,
			admitted: true,
		},
		{
			name: "passkey only",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				g.addPasskey(t, s, "cred-1")
			},
			required: true,
			factors:  []core.Factor{core.FactorPasskeyStepUp, core.FactorRecoveryCode},
			primary:  password,
			admitted: false,
		},
		{
			name: "passkey suspended",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				g.addPasskey(t, s, "cred-1")
				if err := g.passkeys.Suspend(context.Background(), s, passkey.CredentialID("cred-1"), goldenNow); err != nil {
					t.Fatal(err)
				}
			},
			required: false,
			primary:  password,
			admitted: true,
		},
		{
			name: "totp disabled while recovery codes remain",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				g.confirmTOTP(t, s, "h1", "h2")
				if err := g.mfa.DeleteTOTP(context.Background(), s); err != nil {
					t.Fatal(err)
				}
			},
			required: false,
			primary:  password,
			admitted: true,
		},
		{
			name: "passkey-only user logging in with the passkey",
			setup: func(t *testing.T, g goldenStores, s core.Subject) {
				g.addPasskey(t, s, "cred-1")
			},
			required: true,
			factors:  []core.Factor{core.FactorPasskeyStepUp, core.FactorRecoveryCode},
			primary: func(t *testing.T, s core.Subject) core.Verified {
				t.Helper()
				v, err := factors.Passkey(factors.PasskeyCredential{Owner: s, ID: []byte("cred-1")},
					factors.AuthenticatorFlags{UserPresent: true, UserVerified: true}, goldenNow)
				if err != nil {
					t.Fatal(err)
				}
				return v
			},
			admitted: true,
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			g := goldenStores{mfa: mfamem.New(), passkeys: passkeymem.New()}
			s := core.Subject{User: uuid.New()}
			r.setup(t, g, s)
			e, err := issuance.NewEnrollment(g.mfa, g.passkeys)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.MFADecision(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if d.IsZero() || d.Required() != r.required || !slices.Equal(d.Factors(), r.factors) {
				t.Fatalf("decision required=%v factors=%v, want required=%v factors=%v", d.Required(), d.Factors(), r.required, r.factors)
			}
			got, err := e.MFARequired(context.Background(), s)
			if err != nil || got != r.required {
				t.Fatalf("MFARequired = %v, %v; want %v", got, err, r.required)
			}
			if admitted := goldenAdmit(t, s, d, r.primary(t, s)); admitted != r.admitted {
				t.Fatalf("admitted = %v, want %v", admitted, r.admitted)
			}
		})
	}
}

type failingTOTP struct{ mfa.Store }

func (failingTOTP) HasConfirmedTOTP(context.Context, core.Subject) (bool, error) {
	return false, errors.New("mfa store down")
}

type failingPasskeys struct{ passkey.Store }

func (failingPasskeys) HasActive(context.Context, core.Subject) (bool, error) {
	return false, errors.New("passkey store down")
}

func TestEnrolledFailsClosedOnStoreErrors(t *testing.T) {
	s := core.Subject{User: uuid.New()}
	cases := map[string]struct {
		totp     issuance.TOTPEnrollment
		passkeys issuance.PasskeyEnrollment
	}{
		"mfa store":     {totp: failingTOTP{mfamem.New()}, passkeys: passkeymem.New()},
		"passkey store": {totp: mfamem.New(), passkeys: failingPasskeys{passkeymem.New()}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := issuance.NewEnrollment(c.totp, c.passkeys)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.MFADecision(context.Background(), s)
			if !errors.Is(err, httpx.ErrUnavailable) || !d.IsZero() {
				t.Fatalf("MFADecision = %v, %v; want the zero decision and an ErrUnavailable outage", d, err)
			}
			if req, err := e.MFARequired(context.Background(), s); !errors.Is(err, httpx.ErrUnavailable) || !req {
				t.Fatalf("MFARequired = %v, %v; want true and an ErrUnavailable outage", req, err)
			}
		})
	}
}

func TestNewEnrollmentRefusesMissingStores(t *testing.T) {
	if _, err := issuance.NewEnrollment(nil, passkeymem.New()); !errors.Is(err, issuance.ErrInvalidConfig) {
		t.Fatalf("nil TOTP store = %v", err)
	}
	var typed *mfamem.Store
	if _, err := issuance.NewEnrollment(typed, passkeymem.New()); !errors.Is(err, issuance.ErrInvalidConfig) {
		t.Fatalf("typed nil TOTP store = %v", err)
	}
	if _, err := issuance.NewEnrollment(mfamem.New(), nil); !errors.Is(err, issuance.ErrInvalidConfig) {
		t.Fatalf("nil passkey store = %v", err)
	}
}
