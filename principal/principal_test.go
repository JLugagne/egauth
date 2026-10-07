package principal_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
)

func TestTypesAreCoreAliases(t *testing.T) {
	pairs := [][2]reflect.Type{
		{reflect.TypeFor[principal.TenantID](), reflect.TypeFor[core.TenantID]()},
		{reflect.TypeFor[principal.Subject](), reflect.TypeFor[core.Subject]()},
		{reflect.TypeFor[principal.SessionAttrs](), reflect.TypeFor[core.SessionAttrs]()},
		{reflect.TypeFor[principal.Factor](), reflect.TypeFor[core.Factor]()},
		{reflect.TypeFor[principal.Transport](), reflect.TypeFor[core.Transport]()},
		{reflect.TypeFor[principal.Caller](), reflect.TypeFor[core.Caller]()},
		{reflect.TypeFor[principal.Sealed](), reflect.TypeFor[core.Sealed]()},
	}
	for _, p := range pairs {
		require.Equal(t, p[1], p[0])
	}
}

func TestFactorVariablesMatchCore(t *testing.T) {
	got := []principal.Factor{
		principal.FactorEmailCode, principal.FactorEmailLink, principal.FactorExternal, principal.FactorFederated,
		principal.FactorPasskey, principal.FactorPasskeyStepUp, principal.FactorPassword, principal.FactorRecoveryCode,
		principal.FactorSMSCode, principal.FactorTOTP, principal.FactorUserVerification,
	}
	require.Equal(t, core.AllFactors(), got)
}

func TestParseTenantIDDelegates(t *testing.T) {
	id, err := principal.ParseTenantID("acme")
	require.NoError(t, err)
	require.Equal(t, "acme", id.String())
	_, err = principal.ParseTenantID("")
	require.ErrorIs(t, err, core.ErrInvalidTenant)
}

func TestSealedFromBytesCopies(t *testing.T) {
	b := []byte{1, 2}
	s := principal.SealedFromBytes(b)
	b[0] = 7
	require.Equal(t, []byte{1, 2}, s.Bytes())
}
