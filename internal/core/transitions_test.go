package core_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/redirect"
)

func TestAddRules(t *testing.T) {
	v := ok[core.Verified](t)
	pwdAlice := v(factors.Password(alice, t0))
	pwdBob := v(factors.Password(bob, t0))
	credX := factors.PasskeyCredential{Owner: alice, ID: []byte("credential-x")}
	credY := factors.PasskeyCredential{Owner: alice, ID: []byte("credential-y")}
	attackerCred := factors.PasskeyCredential{Owner: bob, ID: []byte("attacker")}

	unbound := pending(t)
	boundPwd := add(t, unbound, pwdAlice, active)
	usernameFirst, err := unbound.Bind(alice, active)
	require.NoError(t, err)
	primaryPK := add(t, unbound, v(factors.Passkey(credX, uv, t0)), active)

	cases := []struct {
		name string
		p    core.Pending
		v    core.Verified
		st   core.AccountState
		want error
	}{
		{"tenant mismatch", unbound, v(factors.Password(aliceB, t0)), active, core.ErrTenantMismatch},
		{"totp cannot bind", unbound, v(factors.TOTP(alice, t0)), active, core.ErrNotBound},
		{"recovery code cannot bind", unbound, v(factors.RecoveryCode(alice, t0)), active, core.ErrNotBound},
		{"passkey step-up cannot bind", unbound, v(factors.PasskeyStepUp(credX, uv, t0)), active, core.ErrNotBound},
		{"C-29 bound subject differs", boundPwd, pwdBob, active, core.ErrSubjectMismatch},
		{"C-29 username-first plus attacker discoverable credential", usernameFirst, v(factors.Passkey(attackerCred, uv, t0)), active, core.ErrSubjectMismatch},
		{"C-29 second factor of another subject", boundPwd, v(factors.TOTP(bob, t0)), active, core.ErrSubjectMismatch},
		{"epoch changed since bind", boundPwd, v(factors.TOTP(alice, t0)), state(4), core.ErrEpochStale},
		{"C-28 step-up reuses primary passkey", primaryPK, v(factors.PasskeyStepUp(credX, uv, t0)), active, core.ErrSameCredential},
		{"verification after expiry", unbound, v(factors.Password(alice, t0.Add(core.PendingTTL))), active, core.ErrPendingExpired},
		{"zero verified", unbound, core.Verified{}, active, core.ErrInvalidArgument},
		{"zero pending", core.Pending{}, pwdAlice, active, core.ErrInvalidArgument},
		{"provider mismatch", add(t, unbound, v(factors.Federated(alice, "google", t0)), active), v(factors.Federated(alice, "github", t0)), active, core.ErrProviderMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.p.Add(c.v, c.st)
			require.ErrorIs(t, err, c.want)
		})
	}

	t.Run("identifying factor binds and records epoch", func(t *testing.T) {
		s, bound := boundPwd.Subject()
		require.True(t, bound)
		require.Equal(t, alice, s)
		require.Equal(t, uint64(3), boundPwd.EpochAtBind())
	})
	t.Run("non-identifying primary cannot bind", func(t *testing.T) {
		nv, err := core.NewVerified(core.VerifiedSpec{Subject: alice, Factors: []core.Factor{core.FactorPasskey, core.FactorUserVerification}, CredentialID: []byte{1}, At: t0})
		require.NoError(t, err)
		_, err = unbound.Add(nv, active)
		require.ErrorIs(t, err, core.ErrNotIdentifying)
	})
	t.Run("username-first accepts the bound subject's passkey", func(t *testing.T) {
		p := add(t, usernameFirst, v(factors.Passkey(credX, uv, t0)), active)
		require.True(t, p.MultiFactor())
	})
	t.Run("C-28 distinct step-up credential is accepted", func(t *testing.T) {
		p := add(t, primaryPK, v(factors.PasskeyStepUp(credY, uv, t0)), active)
		require.ElementsMatch(t, []core.Factor{core.FactorPasskey, core.FactorUserVerification, core.FactorPasskeyStepUp}, p.Factors())
	})
	t.Run("C-28 primary passkey after a step-up with the same credential", func(t *testing.T) {
		p := add(t, usernameFirst, v(factors.PasskeyStepUp(credX, uv, t0)), active)
		_, err := p.Add(v(factors.Passkey(credX, uv, t0)), active)
		require.ErrorIs(t, err, core.ErrSameCredential)
	})
	t.Run("Add does not mutate its receiver", func(t *testing.T) {
		before := boundPwd.Factors()
		_ = add(t, boundPwd, v(factors.TOTP(alice, t0)), active)
		require.Equal(t, before, boundPwd.Factors())
		require.False(t, unbound.Bound())
	})
}

func TestBindRules(t *testing.T) {
	p := pending(t)
	_, err := p.Bind(aliceB, active)
	require.ErrorIs(t, err, core.ErrTenantMismatch)
	_, err = p.Bind(core.Subject{Tenant: tenantA}, active)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	b, err := p.Bind(alice, active)
	require.NoError(t, err)
	_, err = b.Bind(alice, active)
	require.ErrorIs(t, err, core.ErrAlreadyBound)
}

func TestBindHash(t *testing.T) {
	p := pending(t)
	_, err := p.WithBindHash([]byte("short"))
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	h := []byte("0123456789abcdef0123456789abcdef")
	b, err := p.WithBindHash(h)
	require.NoError(t, err)
	require.Equal(t, h, b.BindHash())
	_, err = b.WithBindHash(h)
	require.ErrorIs(t, err, core.ErrInvalidArgument)
}

func TestAdmitRules(t *testing.T) {
	v := ok[core.Verified](t)
	pwd := add(t, pending(t), v(factors.Password(alice, t0)), active)
	bindOnly, err := pending(t).Bind(alice, active)
	require.NoError(t, err)
	reauth := core.PendingForReauth(passwordSession(t), t0)
	reauth = add(t, reauth, v(factors.Password(alice, t0)), active)

	cases := []struct {
		name string
		p    core.Pending
		st   core.AccountState
		now  time.Time
		want error
	}{
		{"unbound", pending(t), active, t0, core.ErrNotBound},
		{"bound without primary", bindOnly, active, t0, core.ErrNoPrimary},
		{"I-12 zero account state", pwd, core.AccountState{}, t0, core.ErrAccountUnusable},
		{"missing account", pwd, core.NewAccountState(false, false, false, false, false, 3), t0, core.ErrAccountUnusable},
		{"disabled account", pwd, core.NewAccountState(true, true, false, false, true, 3), t0, core.ErrAccountUnusable},
		{"deleted account", pwd, core.NewAccountState(true, false, true, false, true, 3), t0, core.ErrAccountUnusable},
		{"epoch bumped since bind", pwd, state(4), t0, core.ErrEpochStale},
		{"expired", pwd, active, t0.Add(core.PendingTTL), core.ErrPendingExpired},
		{"reauth pending", reauth, active, t0, core.ErrReauthPending},
		{"zero pending", core.Pending{}, active, t0, core.ErrInvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			adm, err := core.Admit(c.p, c.st, noMFA, c.now)
			require.ErrorIs(t, err, c.want)
			_, isSession := adm.Session()
			require.False(t, isSession)
			_, _, needs := adm.NeedsFactor()
			require.False(t, needs)
		})
	}

	t.Run("MFA required and single factor needs a factor", func(t *testing.T) {
		adm, err := core.Admit(pwd, active, withMFA, t0)
		require.NoError(t, err)
		_, isSession := adm.Session()
		require.False(t, isSession)
		np, fs, needs := adm.NeedsFactor()
		require.True(t, needs)
		require.Equal(t, []core.Factor{core.FactorRecoveryCode, core.FactorTOTP}, fs)
		s, bound := np.Subject()
		require.True(t, bound)
		require.Equal(t, alice, s)
	})
	t.Run("MFA required, password plus totp", func(t *testing.T) {
		a := passwordTOTPSession(t)
		require.True(t, a.MultiFactor())
		require.True(t, a.SecondAt().Equal(t0.Add(time.Minute)))
		require.True(t, a.PrimaryAt().Equal(t0))
	})
	t.Run("MFA required, single passkey assertion suffices", func(t *testing.T) {
		a := passkeySession(t)
		require.True(t, a.MultiFactor())
		require.True(t, a.PrimaryAt().Equal(t0))
		require.True(t, a.SecondAt().Equal(t0))
	})
	t.Run("I-12 must-change comes from account state", func(t *testing.T) {
		st := core.NewAccountState(true, false, false, true, true, 3)
		a := admitSession(t, add(t, pending(t), v(factors.Password(alice, t0)), st), st, noMFA, t0)
		require.True(t, a.MustChangePassword())
	})
	t.Run("session fields", func(t *testing.T) {
		a := admitSession(t, pwd, active, noMFA, t0.Add(time.Second))
		require.NotEqual(t, uuid.Nil, a.Lineage())
		require.Equal(t, alice, a.Subject())
		require.Equal(t, uint64(3), a.Epoch())
		require.True(t, a.RememberMe())
		require.Equal(t, "/after", a.ReturnTo())
		require.Equal(t, core.TransportCookies, a.Transport())
		require.True(t, a.CreatedAt().Equal(t0.Add(time.Second)))
		require.True(t, a.ClaimsFetchedAt().Equal(t0.Add(time.Second)))
		require.True(t, a.SecondAt().IsZero())
		require.False(t, a.MultiFactor())
		b := admitSession(t, pwd, active, noMFA, t0.Add(time.Second))
		require.NotEqual(t, a.Lineage(), b.Lineage())
	})
}

func TestRenewRules(t *testing.T) {
	pwd := passwordSession(t)
	mf := passwordTOTPSession(t)
	cases := []struct {
		name   string
		a      core.SessionAttrs
		st     core.AccountState
		mfa    core.MFADecision
		claims core.ClaimsOutcome
		want   error
	}{
		{"missing account", pwd, core.NewAccountState(false, false, false, false, false, 3), noMFA, core.ClaimsRefreshed, core.ErrAccountUnusable},
		{"disabled", pwd, core.NewAccountState(true, true, false, false, true, 3), noMFA, core.ClaimsRefreshed, core.ErrAccountUnusable},
		{"deleted", pwd, core.NewAccountState(true, false, true, false, true, 3), noMFA, core.ClaimsRefreshed, core.ErrAccountUnusable},
		{"stale epoch", pwd, state(4), noMFA, core.ClaimsRefreshed, core.ErrEpochStale},
		{"epoch ahead of store", pwd, state(2), noMFA, core.ClaimsRefreshed, core.ErrEpochStale},
		{"MFA enrolled, single-factor session", pwd, active, withMFA, core.ClaimsRefreshed, core.ErrReauthRequired},
		{"claims unavailable", pwd, active, noMFA, core.ClaimsUnavailable, core.ErrClaimsUnavailable},
		{"claims subject unknown", pwd, active, noMFA, core.ClaimsSubjectUnknown, core.ErrClaimsSubjectUnknown},
		{"claims too large", pwd, active, noMFA, core.ClaimsTooLarge, core.ErrClaimsTooLarge},
		{"zero claims outcome", pwd, active, noMFA, 0, core.ErrInvalidArgument},
		{"zero attrs", core.SessionAttrs{}, active, noMFA, core.ClaimsRefreshed, core.ErrInvalidArgument},
		{"multi-factor session under MFA", mf, active, withMFA, core.ClaimsRefreshed, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := core.Renew(c.a, c.st, c.mfa, c.claims, t0.Add(time.Hour))
			if c.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, c.want)
		})
	}

	t.Run("claims outcome timestamps", func(t *testing.T) {
		later := t0.Add(time.Hour)
		r, err := core.Renew(pwd, active, noMFA, core.ClaimsRefreshed, later)
		require.NoError(t, err)
		require.True(t, r.ClaimsFetchedAt().Equal(later))
		r, err = core.Renew(pwd, active, noMFA, core.ClaimsKeptStale, later)
		require.NoError(t, err)
		require.True(t, r.ClaimsFetchedAt().Equal(pwd.ClaimsFetchedAt()))
	})
}

func TestRenewMustChangeOR(t *testing.T) {
	flagged := core.NewAccountState(true, false, false, true, true, 3)
	clean := passwordSession(t)
	stillFlagged := admitSession(t, add(t, pending(t), ok[core.Verified](t)(factors.Password(alice, t0)), flagged), flagged, noMFA, t0)
	cases := []struct {
		name string
		a    core.SessionAttrs
		st   core.AccountState
		want bool
	}{
		{"neither", clean, active, false},
		{"store sets it", clean, flagged, true},
		{"session keeps it when store clears it", stillFlagged, active, true},
		{"both", stillFlagged, flagged, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := core.Renew(c.a, c.st, noMFA, core.ClaimsRefreshed, t0.Add(time.Minute))
			require.NoError(t, err)
			require.Equal(t, c.want, r.MustChangePassword())
		})
	}
}

func TestRenewNeverAddsFactor(t *testing.T) {
	sessions := map[string]core.SessionAttrs{
		"password":          passwordSession(t),
		"password and totp": passwordTOTPSession(t),
		"passkey":           passkeySession(t),
	}
	decisions := map[string]core.MFADecision{
		"none":           noMFA,
		"totp enrolled":  withMFA,
		"every factor":   core.NewMFADecision(core.AllFactors()),
		"passkey stepup": core.NewMFADecision([]core.Factor{core.FactorPasskeyStepUp}),
	}
	outcomes := []core.ClaimsOutcome{core.ClaimsRefreshed, core.ClaimsKeptStale}
	for sn, a := range sessions {
		for dn, d := range decisions {
			for _, o := range outcomes {
				t.Run(sn+"/"+dn, func(t *testing.T) {
					r, err := core.Renew(a, active, d, o, t0.Add(2*time.Hour))
					if err != nil {
						require.ErrorIs(t, err, core.ErrReauthRequired)
						require.False(t, a.MultiFactor())
						return
					}
					require.Equal(t, a.Factors(), r.Factors())
					require.Equal(t, a.AMR(), r.AMR())
					require.Equal(t, a.MultiFactor(), r.MultiFactor())
					require.Equal(t, a.Lineage(), r.Lineage())
					require.True(t, a.PrimaryAt().Equal(r.PrimaryAt()))
					require.True(t, a.SecondAt().Equal(r.SecondAt()))
					require.Equal(t, a.Epoch(), r.Epoch())
					require.Equal(t, a.RememberMe(), r.RememberMe())
					require.Equal(t, a.Transport(), r.Transport())
					require.True(t, a.CreatedAt().Equal(r.CreatedAt()))
				})
			}
		}
	}

	t.Run("T-08 single-factor session of an enrolled user is not upgraded", func(t *testing.T) {
		a := passwordSession(t)
		r, err := core.Renew(a, active, withMFA, core.ClaimsRefreshed, t0.Add(time.Minute))
		require.ErrorIs(t, err, core.ErrReauthRequired)
		require.True(t, r.IsZero())
		require.False(t, a.HasFactor(core.FactorTOTP))
	})

	t.Run("Renew takes no factor input", func(t *testing.T) {
		ft := reflect.TypeFor[core.Factor]()
		vt := reflect.TypeFor[core.Verified]()
		pt := reflect.TypeFor[core.Pending]()
		rt := reflect.TypeOf(core.Renew)
		for i := range rt.NumIn() {
			in := rt.In(i)
			require.NotEqual(t, ft, in)
			require.NotEqual(t, vt, in)
			require.NotEqual(t, pt, in)
			if in.Kind() == reflect.Slice {
				require.NotEqual(t, ft, in.Elem())
			}
		}
	})
}

func TestFreshWithinRoleAware(t *testing.T) {
	v := ok[core.Verified](t)

	t.Run("password session", func(t *testing.T) {
		a := passwordSession(t)
		require.True(t, a.FreshWithin(10*time.Minute, t0.Add(5*time.Minute)))
		require.False(t, a.FreshWithin(10*time.Minute, t0.Add(11*time.Minute)))
		require.False(t, a.FreshWithin(0, t0))
		require.False(t, a.FreshWithin(-time.Minute, t0))
	})
	t.Run("zero attrs are never fresh", func(t *testing.T) {
		require.False(t, core.SessionAttrs{}.FreshWithin(time.Hour, t0))
	})
	t.Run("multi-factor needs both timestamps", func(t *testing.T) {
		a := passwordTOTPSession(t)
		require.True(t, a.FreshWithin(10*time.Minute, t0.Add(5*time.Minute)))
		require.False(t, a.FreshWithin(10*time.Minute, t0.Add(30*time.Minute)))
	})
	t.Run("C-44 password-only reauth does not refresh the second factor", func(t *testing.T) {
		a := passwordTOTPSession(t)
		later := t0.Add(30 * time.Minute)
		p := add(t, core.PendingForReauth(a, later), v(factors.Password(alice, later)), active)
		_, err := core.Reauthenticate(a, p, active, withMFA, later)
		require.ErrorIs(t, err, core.ErrFactorRequired)
		r, err := core.Reauthenticate(a, p, active, noMFA, later)
		require.NoError(t, err)
		require.True(t, r.PrimaryAt().Equal(later))
		require.True(t, r.SecondAt().Equal(a.SecondAt()))
		require.False(t, r.FreshWithin(10*time.Minute, later))
	})
	t.Run("password plus totp reauth is fresh", func(t *testing.T) {
		a := passwordTOTPSession(t)
		later := t0.Add(30 * time.Minute)
		p := add(t, core.PendingForReauth(a, later), v(factors.Password(alice, later)), active)
		p = add(t, p, v(factors.TOTP(alice, later)), active)
		r, err := core.Reauthenticate(a, p, active, withMFA, later)
		require.NoError(t, err)
		require.Equal(t, a.Lineage(), r.Lineage())
		require.True(t, r.FreshWithin(10*time.Minute, later))
	})
	t.Run("C-45 enrolled factor is not fresh until verified", func(t *testing.T) {
		a := passwordSession(t)
		e, err := core.FactorEnrolled(a, core.FactorTOTP, state(4))
		require.NoError(t, err)
		require.True(t, e.HasFactor(core.FactorTOTP))
		require.True(t, e.SecondAt().IsZero())
		require.Equal(t, uint64(4), e.Epoch())
		require.False(t, e.FreshWithin(time.Hour, t0))
	})
	t.Run("passkey session depends on the primary timestamp", func(t *testing.T) {
		a := passkeySession(t)
		require.True(t, a.FreshWithin(10*time.Minute, t0.Add(5*time.Minute)))
		require.False(t, a.FreshWithin(10*time.Minute, t0.Add(11*time.Minute)))
	})
}

func TestReauthenticateRules(t *testing.T) {
	v := ok[core.Verified](t)
	a := passwordSession(t)
	other := passwordSession(t)
	p := add(t, core.PendingForReauth(a, t0), v(factors.Password(alice, t0)), active)

	_, err := core.Reauthenticate(other, p, active, noMFA, t0)
	require.ErrorIs(t, err, core.ErrLineageMismatch)
	login := add(t, pending(t), v(factors.Password(alice, t0)), active)
	_, err = core.Reauthenticate(a, login, active, noMFA, t0)
	require.ErrorIs(t, err, core.ErrLineageMismatch)
	_, err = core.Reauthenticate(a, p, state(4), noMFA, t0)
	require.ErrorIs(t, err, core.ErrEpochStale)
	_, err = core.Reauthenticate(a, p, core.NewAccountState(true, true, false, false, true, 3), noMFA, t0)
	require.ErrorIs(t, err, core.ErrAccountUnusable)
	_, err = core.Reauthenticate(a, p, active, noMFA, t0.Add(core.PendingTTL))
	require.ErrorIs(t, err, core.ErrPendingExpired)
	_, err = core.Reauthenticate(a, core.PendingForReauth(a, t0), active, noMFA, t0)
	require.ErrorIs(t, err, core.ErrNoPrimary)
	_, err = core.PendingForReauth(a, t0).Add(v(factors.Password(bob, t0)), active)
	require.ErrorIs(t, err, core.ErrSubjectMismatch)

	pk := add(t, core.PendingForReauth(a, t0), v(factors.Passkey(factors.PasskeyCredential{Owner: alice, ID: []byte{7}}, uv, t0.Add(time.Minute))), active)
	r, err := core.Reauthenticate(a, pk, active, withMFA, t0.Add(time.Minute))
	require.NoError(t, err)
	require.Equal(t, a.Lineage(), r.Lineage())
	require.True(t, r.HasFactor(core.FactorPassword))
	require.True(t, r.HasFactor(core.FactorPasskey))
	require.True(t, r.MultiFactor())
	require.Equal(t, a.RememberMe(), r.RememberMe())
}

func TestFactorEnrolledRules(t *testing.T) {
	a := passwordSession(t)
	_, err := core.FactorEnrolled(a, core.FactorPasskey, state(4))
	require.ErrorIs(t, err, core.ErrInvalidFactor)
	_, err = core.FactorEnrolled(a, core.Factor{}, state(4))
	require.ErrorIs(t, err, core.ErrInvalidFactor)
	_, err = core.FactorEnrolled(a, core.FactorTOTP, state(3))
	require.ErrorIs(t, err, core.ErrEpochStale)
	_, err = core.FactorEnrolled(a, core.FactorTOTP, state(5))
	require.ErrorIs(t, err, core.ErrEpochStale)
	_, err = core.FactorEnrolled(a, core.FactorTOTP, core.NewAccountState(true, true, false, false, true, 4))
	require.ErrorIs(t, err, core.ErrAccountUnusable)
	_, err = core.FactorEnrolled(core.SessionAttrs{}, core.FactorTOTP, state(4))
	require.ErrorIs(t, err, core.ErrInvalidArgument)
}

func TestPasswordChangedKeepsEveryFactor(t *testing.T) {
	v := ok[core.Verified](t)
	flagged := core.NewAccountState(true, false, false, true, true, 3)
	p := add(t, pending(t), v(factors.Passkey(factors.PasskeyCredential{Owner: alice, ID: []byte{5}}, uv, t0)), flagged)
	p = add(t, p, v(factors.TOTP(alice, t0)), flagged)
	a := admitSession(t, p, flagged, withMFA, t0)
	require.True(t, a.MustChangePassword())

	later := t0.Add(time.Hour)
	r, err := core.PasswordChanged(a, state(4), later)
	require.NoError(t, err)
	for _, f := range a.Factors() {
		require.True(t, r.HasFactor(f), "lost %s", f.Code())
	}
	require.True(t, r.HasFactor(core.FactorPassword))
	require.Subset(t, r.AMR(), a.AMR())
	require.Contains(t, r.AMR(), "hwk")
	require.Contains(t, r.AMR(), "otp")
	require.Contains(t, r.AMR(), "pwd")
	require.Equal(t, a.Lineage(), r.Lineage())
	require.False(t, r.MustChangePassword())
	require.Equal(t, uint64(4), r.Epoch())
	require.True(t, r.PrimaryAt().Equal(later))
	require.True(t, r.SecondAt().Equal(a.SecondAt()))
	require.True(t, r.CreatedAt().Equal(a.CreatedAt()))

	_, err = core.PasswordChanged(a, state(3), later)
	require.ErrorIs(t, err, core.ErrEpochStale)
	_, err = core.PasswordChanged(a, state(6), later)
	require.ErrorIs(t, err, core.ErrEpochStale)
	_, err = core.PasswordChanged(a, core.NewAccountState(true, false, true, false, true, 4), later)
	require.ErrorIs(t, err, core.ErrAccountUnusable)
}

func TestMagicLinkAMRIsEmail(t *testing.T) {
	v := ok[core.Verified](t)
	a := admitSession(t, add(t, pending(t), v(factors.EmailLink(alice, t0)), active), active, noMFA, t0)
	require.Equal(t, []string{"email"}, a.AMR())
	require.NotContains(t, a.AMR(), "otp")
	require.False(t, a.HasFactor(core.FactorTOTP))
	require.False(t, a.HasFactor(core.FactorEmailCode))
	require.False(t, a.MultiFactor())
}

func TestNewPendingAppliesRememberPolicyOnce(t *testing.T) {
	cases := []struct {
		pol    core.RememberMePolicy
		intent core.RememberIntent
		want   bool
	}{
		{core.RememberUserChoice, core.RememberRequested, true},
		{core.RememberUserChoice, core.RememberDeclined, false},
		{core.RememberAlways, core.RememberRequested, true},
		{core.RememberAlways, core.RememberDeclined, true},
		{core.RememberNever, core.RememberRequested, false},
		{core.RememberNever, core.RememberDeclined, false},
	}
	for _, c := range cases {
		p := pendingWith(t, c.intent, c.pol)
		require.Equal(t, c.want, p.RememberMe())
		p = add(t, p, ok[core.Verified](t)(factors.Password(alice, t0)), active)
		a := admitSession(t, p, active, noMFA, t0)
		require.Equal(t, c.want, a.RememberMe())
		r, err := core.Renew(a, active, noMFA, core.ClaimsRefreshed, t0.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, c.want, r.RememberMe())
		rp := core.PendingForReauth(a, t0)
		require.Equal(t, c.want, rp.RememberMe())
		rp = add(t, rp, ok[core.Verified](t)(factors.Password(alice, t0)), active)
		ra, err := core.Reauthenticate(a, rp, active, noMFA, t0)
		require.NoError(t, err)
		require.Equal(t, c.want, ra.RememberMe())
		pc, err := core.PasswordChanged(a, state(4), t0)
		require.NoError(t, err)
		require.Equal(t, c.want, pc.RememberMe())
	}

	t.Run("invalid inputs", func(t *testing.T) {
		_, err := core.NewPending(tenantA, 0, redirect.Target{}, core.TransportCookies, core.RememberAlways, t0)
		require.ErrorIs(t, err, core.ErrInvalidArgument)
		_, err = core.NewPending(tenantA, core.RememberDeclined, redirect.Target{}, core.TransportCookies, 0, t0)
		require.ErrorIs(t, err, core.ErrInvalidArgument)
		_, err = core.NewPending(tenantA, core.RememberDeclined, redirect.Target{}, 0, core.RememberAlways, t0)
		require.ErrorIs(t, err, core.ErrInvalidArgument)
		_, err = core.NewPending(tenantA, core.RememberDeclined, redirect.Target{}, core.TransportBearer, core.RememberAlways, time.Time{})
		require.ErrorIs(t, err, core.ErrInvalidArgument)
	})

	t.Run("only NewPending reads the policy or the intent", func(t *testing.T) {
		pol := reflect.TypeFor[core.RememberMePolicy]()
		intent := reflect.TypeFor[core.RememberIntent]()
		others := []any{
			core.PendingForReauth, core.Pending.Add, core.Pending.Bind, core.Admit, core.Reauthenticate,
			core.FactorEnrolled, core.PasswordChanged, core.Renew, core.NewAccountState, core.NewMFADecision,
		}
		for _, fn := range others {
			ft := reflect.TypeOf(fn)
			for i := range ft.NumIn() {
				require.NotEqual(t, pol, ft.In(i), "%s takes the policy", ft)
				require.NotEqual(t, intent, ft.In(i), "%s takes the intent", ft)
			}
		}
	})
}

func TestPendingForReauthIsBound(t *testing.T) {
	a := passwordSession(t)
	p := core.PendingForReauth(a, t0)
	s, bound := p.Subject()
	require.True(t, bound)
	require.Equal(t, alice, s)
	lin, isReauth := p.ReauthOf()
	require.True(t, isReauth)
	require.Equal(t, a.Lineage(), lin)
	require.Equal(t, a.Epoch(), p.EpochAtBind())
	require.Equal(t, a.Transport(), p.Transport())
	require.True(t, p.ExpiresAt().Equal(t0.Add(core.PendingTTL)))
}
