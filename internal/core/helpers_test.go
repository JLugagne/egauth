package core_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/redirect"
)

var (
	t0      = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tenantA = mustTenant("tenant-a")
	tenantB = mustTenant("tenant-b")
	alice   = core.Subject{Tenant: tenantA, User: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}
	bob     = core.Subject{Tenant: tenantA, User: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")}
	aliceB  = core.Subject{Tenant: tenantB, User: alice.User}
	active  = core.NewAccountState(true, false, false, false, true, 3)
	noMFA   = core.NewMFADecision(nil)
	withMFA = core.NewMFADecision([]core.Factor{core.FactorTOTP, core.FactorRecoveryCode})
	uv      = factors.AuthenticatorFlags{UserPresent: true, UserVerified: true}
)

func mustTenant(s string) core.TenantID {
	t, err := core.ParseTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

func state(epoch uint64) core.AccountState {
	return core.NewAccountState(true, false, false, false, true, epoch)
}

func pending(t *testing.T) core.Pending {
	t.Helper()
	return pendingWith(t, core.RememberRequested, core.RememberUserChoice)
}

func pendingWith(t *testing.T, intent core.RememberIntent, pol core.RememberMePolicy) core.Pending {
	t.Helper()
	return pendingWithAt(t, intent, pol, t0)
}

func pendingAt(t *testing.T, now time.Time) core.Pending {
	t.Helper()
	return pendingWithAt(t, core.RememberRequested, core.RememberUserChoice, now)
}

func pendingWithAt(t *testing.T, intent core.RememberIntent, pol core.RememberMePolicy, now time.Time) core.Pending {
	t.Helper()
	o, err := redirect.NewOrigins("https://app.example.com", nil)
	require.NoError(t, err)
	rt, err := redirect.Parse("/after", o)
	require.NoError(t, err)
	p, err := core.NewPending(tenantA, intent, rt, core.TransportCookies, pol, now)
	require.NoError(t, err)
	return p
}

func ok[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		require.NoError(t, err)
		return v
	}
}

func add(t *testing.T, p core.Pending, v core.Verified, st core.AccountState) core.Pending {
	t.Helper()
	n, err := p.Add(v, st)
	require.NoError(t, err)
	return n
}

func admitSession(t *testing.T, p core.Pending, st core.AccountState, mfa core.MFADecision, now time.Time) core.SessionAttrs {
	t.Helper()
	adm, err := core.Admit(p, st, mfa, now)
	require.NoError(t, err)
	a, isSession := adm.Session()
	require.True(t, isSession)
	return a
}

func passwordSession(t *testing.T) core.SessionAttrs {
	t.Helper()
	v := ok[core.Verified](t)(factors.Password(alice, t0))
	return admitSession(t, add(t, pending(t), v, active), active, noMFA, t0)
}

func passwordTOTPSession(t *testing.T) core.SessionAttrs {
	t.Helper()
	p := add(t, pending(t), ok[core.Verified](t)(factors.Password(alice, t0)), active)
	p = add(t, p, ok[core.Verified](t)(factors.TOTP(alice, t0.Add(time.Minute))), active)
	return admitSession(t, p, active, withMFA, t0.Add(time.Minute))
}

func passkeySession(t *testing.T) core.SessionAttrs {
	t.Helper()
	v := ok[core.Verified](t)(factors.Passkey(factors.PasskeyCredential{Owner: alice, ID: []byte{9, 9}}, uv, t0))
	return admitSession(t, add(t, pending(t), v, active), active, withMFA, t0)
}
