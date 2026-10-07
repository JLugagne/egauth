package factors_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
)

var (
	at      = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	subject = core.Subject{User: uuid.MustParse("11111111-2222-4333-8444-555555555555")}
	cred    = factors.PasskeyCredential{Owner: subject, ID: []byte{1, 2, 3}}
	uvFlags = factors.AuthenticatorFlags{UserPresent: true, UserVerified: true}
)

func TestConstructorsYieldExpectedFactors(t *testing.T) {
	type build func() (core.Verified, error)
	cases := []struct {
		name       string
		build      build
		want       []core.Factor
		identifies bool
		provider   string
		cred       bool
	}{
		{"password", func() (core.Verified, error) { return factors.Password(subject, at) }, []core.Factor{core.FactorPassword}, true, "", false},
		{"email link", func() (core.Verified, error) { return factors.EmailLink(subject, at) }, []core.Factor{core.FactorEmailLink}, true, "", false},
		{"email code", func() (core.Verified, error) { return factors.EmailCode(subject, at) }, []core.Factor{core.FactorEmailCode}, true, "", false},
		{"sms code", func() (core.Verified, error) { return factors.SMSCode(subject, at) }, []core.Factor{core.FactorSMSCode}, true, "", false},
		{"federated", func() (core.Verified, error) { return factors.Federated(subject, "google", at) }, []core.Factor{core.FactorFederated}, true, "google", false},
		{"external", func() (core.Verified, error) { return factors.External(subject, "ldap", at) }, []core.Factor{core.FactorExternal}, true, "external:ldap", false},
		{"passkey", func() (core.Verified, error) { return factors.Passkey(cred, uvFlags, at) }, []core.Factor{core.FactorPasskey, core.FactorUserVerification}, true, "", true},
		{"passkey step-up", func() (core.Verified, error) { return factors.PasskeyStepUp(cred, uvFlags, at) }, []core.Factor{core.FactorPasskeyStepUp}, false, "", true},
		{"totp", func() (core.Verified, error) { return factors.TOTP(subject, at) }, []core.Factor{core.FactorTOTP}, false, "", false},
		{"recovery code", func() (core.Verified, error) { return factors.RecoveryCode(subject, at) }, []core.Factor{core.FactorRecoveryCode}, false, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.build()
			require.NoError(t, err)
			require.ElementsMatch(t, c.want, v.Factors())
			require.Equal(t, c.identifies, v.Identifies())
			require.Equal(t, c.provider, v.Provider())
			require.Equal(t, subject, v.Subject())
			require.True(t, v.At().Equal(at))
			require.Equal(t, c.cred, len(v.CredentialID()) > 0)
		})
	}
}

func TestMagicLinkIsNeverOTP(t *testing.T) {
	v, err := factors.EmailLink(subject, at)
	require.NoError(t, err)
	require.Equal(t, []core.Factor{core.FactorEmailLink}, v.Factors())
	require.Equal(t, "email", core.FactorEmailLink.AMR())
	require.NotContains(t, v.Factors(), core.FactorTOTP)
	require.NotContains(t, v.Factors(), core.FactorEmailCode)
}

func TestPasskeyRefusals(t *testing.T) {
	_, err := factors.Passkey(cred, factors.AuthenticatorFlags{UserPresent: true}, at)
	require.ErrorIs(t, err, factors.ErrUserVerificationRequired)
	_, err = factors.PasskeyStepUp(cred, factors.AuthenticatorFlags{UserPresent: true}, at)
	require.ErrorIs(t, err, factors.ErrUserVerificationRequired)
	_, err = factors.Passkey(cred, factors.AuthenticatorFlags{UserVerified: true}, at)
	require.ErrorIs(t, err, factors.ErrUserPresenceRequired)
	suspended := cred
	suspended.Suspended = true
	_, err = factors.Passkey(suspended, uvFlags, at)
	require.ErrorIs(t, err, factors.ErrCredentialSuspended)
	_, err = factors.PasskeyStepUp(suspended, uvFlags, at)
	require.ErrorIs(t, err, factors.ErrCredentialSuspended)
	noID := cred
	noID.ID = nil
	_, err = factors.Passkey(noID, uvFlags, at)
	require.ErrorIs(t, err, factors.ErrMissingCredentialID)
}

func TestInvalidInputs(t *testing.T) {
	_, err := factors.Password(core.Subject{}, at)
	require.ErrorIs(t, err, core.ErrInvalidVerified)
	_, err = factors.TOTP(subject, time.Time{})
	require.ErrorIs(t, err, core.ErrInvalidVerified)
	_, err = factors.Federated(subject, "", at)
	require.ErrorIs(t, err, factors.ErrMissingProvider)
	_, err = factors.External(subject, "", at)
	require.ErrorIs(t, err, factors.ErrMissingProvider)
}

func TestFederatedCannotImpersonateExternalProvider(t *testing.T) {
	ext, err := factors.External(subject, "ldap", at)
	require.NoError(t, err)
	_, err = factors.Federated(subject, ext.Provider(), at)
	require.ErrorIs(t, err, factors.ErrReservedProvider)
	_, err = factors.Federated(subject, factors.ExternalProviderPrefix, at)
	require.ErrorIs(t, err, factors.ErrReservedProvider)
}
