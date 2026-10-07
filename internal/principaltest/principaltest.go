// Package principaltest builds fully populated session state for tests. It is the only allowed
// caller of the core ForTest constructors (G6) and is importable from tests only (G15).
package principaltest

import (
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
)

var (
	fullTenant  = mustTenant("tenant-full")
	fullSubject = core.Subject{Tenant: fullTenant, User: uuid.MustParse("6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5")}
	fullBase    = time.Date(2026, 10, 8, 9, 30, 15, 123456789, time.UTC)
)

func mustTenant(s string) core.TenantID {
	t, err := core.ParseTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

// Full returns SessionAttrs with every field set to a non-zero value. Store and codec suites
// round-trip it through Seal and Unseal and compare with reflect.DeepEqual, so a field added to
// SessionAttrs without codec support fails them. The value is deterministic.
func Full() core.SessionAttrs {
	return core.ForTestSessionAttrs(core.ForTestAttrs{
		Lineage: uuid.MustParse("0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d"),
		Subject: fullSubject,
		Factors: []core.Factor{
			core.FactorPasskey, core.FactorUserVerification, core.FactorPassword, core.FactorTOTP,
			core.FactorPasskeyStepUp, core.FactorFederated,
		},
		Credentials: []core.ForTestCredential{
			{Factor: core.FactorPasskey, ID: []byte{0x01, 0x02, 0x03, 0x04}},
			{Factor: core.FactorPasskeyStepUp, ID: []byte{0x0a, 0x0b, 0x0c}},
		},
		PrimaryAt:       fullBase.Add(-10 * time.Minute),
		SecondAt:        fullBase.Add(-9 * time.Minute),
		Epoch:           7,
		MustChange:      true,
		RememberMe:      true,
		ReturnTo:        "/settings/security?tab=mfa",
		Transport:       core.TransportBearer,
		Provider:        "google",
		CreatedAt:       fullBase.Add(-24 * time.Hour),
		ClaimsFetchedAt: fullBase.Add(-2 * time.Minute),
	})
}

// FullPending returns a bound Pending with every field set to a non-zero value, for the same
// round-trip suites as Full.
func FullPending() core.Pending {
	return core.ForTestPending(core.ForTestPendingFields{
		Subject:     fullSubject,
		EpochAtBind: 7,
		Verified: []core.ForTestVerified{
			{Factors: []core.Factor{core.FactorFederated}, Identifies: true, Provider: "google", At: fullBase.Add(-3 * time.Minute)},
			{Factors: []core.Factor{core.FactorPasskeyStepUp}, CredentialID: []byte{0x0a, 0x0b}, At: fullBase.Add(-1 * time.Minute)},
		},
		RememberMe: true,
		ReturnTo:   "/billing",
		Transport:  core.TransportCookies,
		Provider:   "google",
		ReauthOf:   uuid.MustParse("0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d"),
		BindHash:   []byte("0123456789abcdef0123456789abcdef"),
		ExpiresAt:  fullBase.Add(10 * time.Minute),
	})
}
