package core_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
)

func TestParseTenantID(t *testing.T) {
	for _, good := range []string{"a", "acme", "Acme_Corp-1.eu", "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5", strings.Repeat("x", 128)} {
		id, err := core.ParseTenantID(good)
		require.NoError(t, err, good)
		require.Equal(t, good, id.String())
		require.False(t, id.IsZero())
	}
	for _, bad := range []string{"", " ", "a b", "a:b", "a/b", "a\x00b", "é", strings.Repeat("x", 129)} {
		_, err := core.ParseTenantID(bad)
		require.ErrorIs(t, err, core.ErrInvalidTenant, bad)
	}
	require.True(t, core.TenantID{}.IsZero())
	require.Equal(t, "", core.TenantID{}.String())
}

func TestFactorTable(t *testing.T) {
	wantAMR := map[core.Factor]string{
		core.FactorPassword:         "pwd",
		core.FactorEmailLink:        "email",
		core.FactorEmailCode:        "otp",
		core.FactorSMSCode:          "sms",
		core.FactorFederated:        "fed",
		core.FactorExternal:         "ext",
		core.FactorPasskey:          "hwk",
		core.FactorUserVerification: "user",
		core.FactorTOTP:             "otp",
		core.FactorRecoveryCode:     "rc",
		core.FactorPasskeyStepUp:    "hwk",
	}
	wantRole := map[core.Factor]core.FactorRole{
		core.FactorPassword:         core.RolePrimary,
		core.FactorEmailLink:        core.RolePrimary,
		core.FactorEmailCode:        core.RolePrimary,
		core.FactorSMSCode:          core.RolePrimary,
		core.FactorFederated:        core.RolePrimary,
		core.FactorExternal:         core.RolePrimary,
		core.FactorPasskey:          core.RolePrimary,
		core.FactorUserVerification: core.RoleQualifier,
		core.FactorTOTP:             core.RoleSecond,
		core.FactorRecoveryCode:     core.RoleSecond,
		core.FactorPasskeyStepUp:    core.RoleSecond,
	}
	all := core.AllFactors()
	require.Len(t, all, len(wantAMR))
	codes := map[string]bool{}
	for _, f := range all {
		require.True(t, f.Valid())
		require.False(t, codes[f.Code()], "duplicate code %s", f.Code())
		codes[f.Code()] = true
		require.Equal(t, wantAMR[f], f.AMR(), f.Code())
		require.Equal(t, wantRole[f], f.Role(), f.Code())
		back, err := core.FactorByCode(f.Code())
		require.NoError(t, err)
		require.Equal(t, f, back)
	}
	_, err := core.FactorByCode("otp")
	require.ErrorIs(t, err, core.ErrInvalidFactor)
	_, err = core.FactorByCode("")
	require.ErrorIs(t, err, core.ErrInvalidFactor)
	require.False(t, core.Factor{}.Valid())
	require.Equal(t, core.FactorRole(0), core.Factor{}.Role())
	require.False(t, passwordSession(t).HasFactor(core.Factor{}))
}

func TestNewVerifiedShapes(t *testing.T) {
	cases := []struct {
		name string
		spec core.VerifiedSpec
	}{
		{"zero subject", core.VerifiedSpec{Factors: []core.Factor{core.FactorPassword}, Identifies: true, At: t0}},
		{"zero time", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword}, Identifies: true}},
		{"no factor", core.VerifiedSpec{Subject: alice, At: t0}},
		{"zero factor", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{{}}, At: t0}},
		{"duplicate factor", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword, core.FactorPassword}, At: t0}},
		{"two primaries", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword, core.FactorEmailLink}, At: t0}},
		{"primary and second", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword, core.FactorTOTP}, At: t0}},
		{"identifying second", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorTOTP}, Identifies: true, At: t0}},
		{"uv alone", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorUserVerification}, At: t0}},
		{"uv with password", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword, core.FactorUserVerification}, At: t0}},
		{"passkey without uv", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPasskey}, CredentialID: []byte{1}, At: t0}},
		{"passkey without credential", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPasskey, core.FactorUserVerification}, At: t0}},
		{"password with credential", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword}, CredentialID: []byte{1}, At: t0}},
		{"federated without provider", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorFederated}, At: t0}},
		{"password with provider", core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPassword}, Provider: "x", At: t0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := core.NewVerified(c.spec)
			require.ErrorIs(t, err, core.ErrInvalidVerified)
		})
	}
}

func TestMFADecision(t *testing.T) {
	require.True(t, core.MFADecision{}.IsZero())
	require.True(t, core.MFADecision{}.Required())
	require.False(t, core.NewMFADecision(nil).IsZero())
	require.False(t, core.NewMFADecision(nil).Required())
	require.False(t, core.NewMFADecision([]core.Factor{}).Required())
	require.True(t, core.NewMFADecision([]core.Factor{{}}).Required())
	d := core.NewMFADecision([]core.Factor{core.FactorTOTP, core.FactorRecoveryCode, core.FactorTOTP})
	require.Equal(t, []core.Factor{core.FactorRecoveryCode, core.FactorTOTP}, d.Factors())
}

func TestAccountStateZeroIsUnusable(t *testing.T) {
	require.False(t, core.AccountState{}.Usable())
	require.True(t, active.Usable())
}

func TestCaller(t *testing.T) {
	a := passwordSession(t)
	stored := uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	c, err := core.SessionCaller(a, stored, []byte{1, 2})
	require.NoError(t, err)
	require.Equal(t, core.CallerSession, c.Kind())
	gotStored, gotKey, bound := c.Stored()
	require.True(t, bound)
	require.Equal(t, stored, gotStored)
	require.Equal(t, []byte{1, 2}, gotKey)
	require.Equal(t, tenantA, c.Tenant())
	s, ok := c.Subject()
	require.True(t, ok)
	require.Equal(t, alice, s)
	got, isSession := c.Session()
	require.True(t, isSession)
	require.Equal(t, a.Lineage(), got.Lineage())
	_, isKey := c.APIKey()
	require.False(t, isKey)

	_, err = core.SessionCaller(core.SessionAttrs{}, stored, nil)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	_, err = core.SessionCaller(a, uuid.Nil, nil)
	require.ErrorIs(t, err, core.ErrInvalidArgument, "a session caller is always bound to its stored session")

	rt, err := core.ResourceTokenCaller(a)
	require.NoError(t, err)
	require.Equal(t, core.CallerResourceToken, rt.Kind())
	_, isSession = rt.Session()
	require.False(t, isSession, "a resource token is not a session caller")
	_, _, bound = rt.Stored()
	require.False(t, bound)
	_, err = core.ResourceTokenCaller(core.SessionAttrs{})
	require.ErrorIs(t, err, core.ErrInvalidArgument)

	key := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	k, err := core.APIKeyCaller(alice, key)
	require.NoError(t, err)
	require.Equal(t, core.CallerAPIKey, k.Kind())
	id, isKey := k.APIKey()
	require.True(t, isKey)
	require.Equal(t, key, id)
	_, isSession = k.Session()
	require.False(t, isSession)
	_, err = core.APIKeyCaller(alice, uuid.Nil)
	require.ErrorIs(t, err, core.ErrInvalidArgument)

	sys, err := core.SystemCaller(tenantB, "nightly erase")
	require.NoError(t, err)
	require.Equal(t, core.CallerSystem, sys.Kind())
	require.Equal(t, tenantB, sys.Tenant())
	require.Equal(t, "nightly erase", sys.Reason())
	_, hasSubject := sys.Subject()
	require.False(t, hasSubject)
	_, err = core.SystemCaller(tenantB, "")
	require.ErrorIs(t, err, core.ErrInvalidArgument)

	require.Equal(t, core.CallerKind(0), core.Caller{}.Kind())
}

func TestSealedClaimsCopies(t *testing.T) {
	b := []byte(`{"roles":["admin"]}`)
	c := core.NewSealedClaims(b)
	b[0] = 'X'
	require.Equal(t, byte('{'), c.Bytes()[0])
	out := c.Bytes()
	out[0] = 'Y'
	require.Equal(t, byte('{'), c.Bytes()[0])
	require.Equal(t, len(b), c.Len())
}
