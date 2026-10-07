package core_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
)

func TestZeroMFADecisionIsRefused(t *testing.T) {
	v := ok[core.Verified](t)
	pwd := add(t, pending(t), v(factors.Password(alice, t0)), active)
	a := passwordSession(t)
	reauth := add(t, core.PendingForReauth(a, t0), v(factors.Password(alice, t0)), active)

	cases := []struct {
		name string
		run  func(*testing.T, core.MFADecision) error
	}{
		{"Admit", func(t *testing.T, d core.MFADecision) error {
			adm, err := core.Admit(pwd, active, d, t0)
			_, isSession := adm.Session()
			require.Equal(t, err == nil, isSession)
			return err
		}},
		{"Reauthenticate", func(_ *testing.T, d core.MFADecision) error {
			_, err := core.Reauthenticate(a, reauth, active, d, t0)
			return err
		}},
		{"Renew", func(_ *testing.T, d core.MFADecision) error {
			_, err := core.Renew(a, active, d, core.ClaimsRefreshed, t0.Add(time.Minute))
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name+" refuses the zero decision", func(t *testing.T) {
			require.ErrorIs(t, c.run(t, core.MFADecision{}), core.ErrInvalidArgument)
		})
		t.Run(c.name+" accepts an explicit none-required decision", func(t *testing.T) {
			require.NoError(t, c.run(t, core.NewMFADecision(nil)))
		})
	}
}

func TestReauthWithPasswordAloneLeavesPasskeySessionStale(t *testing.T) {
	a := passkeySession(t)
	later := t0.Add(30 * time.Minute)
	p := add(t, core.PendingForReauth(a, later), ok[core.Verified](t)(factors.Password(alice, later)), active)
	r, err := core.Reauthenticate(a, p, active, noMFA, later)
	require.NoError(t, err)
	require.True(t, r.MultiFactor())
	require.True(t, r.PrimaryAt().Equal(later))
	require.True(t, r.SecondAt().Equal(t0))
	require.False(t, r.FreshWithin(10*time.Minute, later), "C-44: a password alone made a passkey session fresh")
}

func TestPendingForReauthOfZeroAttrsIsInvalid(t *testing.T) {
	single := core.Subject{User: alice.User}
	rp := core.PendingForReauth(core.SessionAttrs{}, t0)
	_, err := rp.Add(ok[core.Verified](t)(factors.Password(single, t0)), active)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	_, err = core.Admit(rp, active, noMFA, t0)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	_, err = core.SealPending(rp)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
}

func TestProducersRefuseWhatConsumersRefuse(t *testing.T) {
	t.Run("Admit refuses a Pending without a valid transport", func(t *testing.T) {
		p := core.ForTestPending(core.ForTestPendingFields{
			Subject:     alice,
			EpochAtBind: 3,
			Verified:    []core.ForTestVerified{{Factors: []core.Factor{core.FactorPassword}, Identifies: true, At: t0}},
			ExpiresAt:   t0.Add(core.PendingTTL),
		})
		_, err := core.Admit(p, active, noMFA, t0)
		require.ErrorIs(t, err, core.ErrInvalidArgument)
		_, err = core.SealPending(p)
		require.ErrorIs(t, err, core.ErrInvalidArgument)
	})
	t.Run("Seal refuses attributes Unseal would refuse", func(t *testing.T) {
		valid := core.ForTestAttrs{
			Lineage:   uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
			Subject:   alice,
			Factors:   []core.Factor{core.FactorPassword},
			PrimaryAt: t0,
			Transport: core.TransportCookies,
			CreatedAt: t0,
		}
		_, err := core.Seal(core.ForTestSessionAttrs(valid))
		require.NoError(t, err)
		bad := map[string]func(*core.ForTestAttrs){
			"zero transport": func(f *core.ForTestAttrs) { f.Transport = 0 },
			"nil lineage":    func(f *core.ForTestAttrs) { f.Lineage = uuid.Nil },
			"zero subject":   func(f *core.ForTestAttrs) { f.Subject = core.Subject{} },
			"no primary":     func(f *core.ForTestAttrs) { f.Factors = []core.Factor{core.FactorTOTP} },
			"credential of a password": func(f *core.ForTestAttrs) {
				f.Credentials = []core.ForTestCredential{{Factor: core.FactorPassword, ID: []byte{1}}}
			},
			"credential of an absent passkey": func(f *core.ForTestAttrs) {
				f.Credentials = []core.ForTestCredential{{Factor: core.FactorPasskey, ID: []byte{1}}}
			},
		}
		for name, mutate := range bad {
			f := valid
			mutate(&f)
			_, err := core.Seal(core.ForTestSessionAttrs(f))
			require.ErrorIs(t, err, core.ErrInvalidArgument, name)
		}
	})
}

func TestUnsealPendingRefusesImpossibleVerified(t *testing.T) {
	p := add(t, pending(t), ok[core.Verified](t)(factors.Password(alice, t0)), active)
	s, err := core.SealPending(p)
	require.NoError(t, err)
	one := []byte{1, 3, 'p', 'w', 'd'}
	require.Equal(t, 1, bytes.Count(s.Bytes(), one))
	forged := bytes.Replace(s.Bytes(), one, []byte{3, 3, 'p', 'w', 'd', 2, 'r', 'c', 4, 't', 'o', 't', 'p'}, 1)
	_, err = core.UnsealPending(core.SealedFromBytes(forged))
	require.ErrorIs(t, err, core.ErrMalformed)

	_, err = core.SealPending(core.ForTestPending(core.ForTestPendingFields{
		Subject:   alice,
		Verified:  []core.ForTestVerified{{Factors: []core.Factor{core.FactorPassword, core.FactorTOTP, core.FactorRecoveryCode}, Identifies: true, At: t0}},
		Transport: core.TransportCookies,
		ExpiresAt: t0.Add(core.PendingTTL),
	}))
	require.ErrorIs(t, err, core.ErrInvalidArgument)
}

func TestUnsealRefusesNonPasskeyCredential(t *testing.T) {
	a := passwordSession(t)
	p := add(t, core.PendingForReauth(a, t0), ok[core.Verified](t)(factors.Passkey(factors.PasskeyCredential{Owner: alice, ID: []byte{7}}, uv, t0)), active)
	r, err := core.Reauthenticate(a, p, active, noMFA, t0)
	require.NoError(t, err)
	s, err := core.Seal(r)
	require.NoError(t, err)
	_, err = core.Unseal(s)
	require.NoError(t, err)
	use := []byte{1, 2, 'p', 'k', 1, 7}
	require.Equal(t, 1, bytes.Count(s.Bytes(), use))
	forged := bytes.Replace(s.Bytes(), use, []byte{1, 3, 'p', 'w', 'd', 1, 7}, 1)
	_, err = core.Unseal(core.SealedFromBytes(forged))
	require.ErrorIs(t, err, core.ErrMalformed)
}
