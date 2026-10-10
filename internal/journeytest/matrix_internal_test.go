package journeytest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
)

type recordedFatal struct{ msg string }

type fatalRecorder struct{ testing.TB }

func (f fatalRecorder) Helper() {}

func (f fatalRecorder) Fatalf(format string, args ...any) {
	panic(recordedFatal{msg: fmt.Sprintf(format, args...)})
}

func (f fatalRecorder) Fatal(args ...any) { panic(recordedFatal{msg: fmt.Sprint(args...)}) }

func fatalOf(fn func()) (msg string, failed bool) {
	defer func() {
		if v := recover(); v != nil {
			rf, ok := v.(recordedFatal)
			if !ok {
				panic(v)
			}
			msg, failed = rf.msg, true
		}
	}()
	fn()
	return "", false
}

func carrierRun(t *testing.T, cell Cell, world Settings, bearerLogin bool) (*Run, *Client) {
	t.Helper()
	w := NewWorld(t, world)
	email := w.FreshEmail("carrier")
	w.SeedUser(email, false)
	c := w.NewClient()
	c.Login(email, bearerLogin)
	return &Run{T: fatalRecorder{TB: t}, World: w, Cell: cell}, c
}

func TestMatrixExpectedFactorsFollowTheDesignExample(t *testing.T) {
	factors, amr := expectedFactors([]string{"email_link"}, "totp")
	require.Equal(t, []string{"email_link", "totp"}, factors)
	require.Equal(t, []string{"email", "otp", "mfa"}, amr)
}

func TestMatrixExpectedFactorsOfASingleFactor(t *testing.T) {
	factors, amr := expectedFactors([]string{"pwd"}, "")
	require.Equal(t, []string{"pwd"}, factors)
	require.Equal(t, []string{"pwd"}, amr)
}

func TestMatrixExpectedFactorsOfAUserVerifiedPasskeyAreMultiFactor(t *testing.T) {
	factors, amr := expectedFactors([]string{"pk", "uv"}, "")
	require.Equal(t, []string{"pk", "uv"}, factors)
	require.Equal(t, []string{"hwk", "user", "mfa"}, amr)
}

func TestMatrixExpectedFactorsAreSortedByCode(t *testing.T) {
	factors, amr := expectedFactors([]string{"pwd"}, "pk_stepup")
	require.Equal(t, []string{"pk_stepup", "pwd"}, factors)
	require.Equal(t, []string{"hwk", "pwd", "mfa"}, amr)
}

func TestMatrixExpectedEventsOrderTheChallengeAroundTheIssuance(t *testing.T) {
	register, _ := primaryDriverOf(PrimaryRegister)
	password, _ := primaryDriverOf(PrimaryPassword)
	totp, _ := secondDriverOf(MFATOTP)
	stepUp, _ := secondDriverOf(MFAPasskeyStepUp)
	issue := []event.Type{event.SessionIssued, event.LoginSucceeded}

	require.Equal(t, append([]event.Type{event.UserRegistered}, issue...), expectedEvents(register, SecondDriver{}, false, false))
	require.Equal(t, issue, expectedEvents(password, SecondDriver{}, false, false))
	require.Equal(t, []event.Type{event.MFAChallengeRequired, event.MFAVerified, event.SessionIssued, event.LoginSucceeded}, expectedEvents(password, totp, true, false))
	require.Equal(t, []event.Type{event.MFAChallengeRequired, event.SessionIssued, event.LoginSucceeded, event.MFAVerified}, expectedEvents(password, stepUp, true, false))
}

func TestMatrixParkedResponsesAreRecognized(t *testing.T) {
	require.True(t, isParked(&Resp{Status: http.StatusOK, Body: []byte(`{"state":"mfa_required"}`)}))
	require.True(t, isParked(&Resp{Status: http.StatusSeeOther, Header: http.Header{"Location": {mfaPage}}}))
	require.False(t, isParked(&Resp{Status: http.StatusOK, Body: []byte(`{"state":"authenticated"}`)}))
	require.False(t, isParked(&Resp{Status: http.StatusSeeOther, Header: http.Header{"Location": {JourneyReturnTo}}}))
}

func TestMatrixViewsDifferOnEveryMember(t *testing.T) {
	base := SessionView{Subject: "s", Tenant: "t", Factors: []string{"pwd"}, AMR: []string{"pwd"}, RememberMe: true, ReturnTo: "/app"}
	require.True(t, equalViews(base, base))
	for name, mutate := range map[string]func(*SessionView){
		"subject":  func(v *SessionView) { v.Subject = "x" },
		"tenant":   func(v *SessionView) { v.Tenant = "x" },
		"factors":  func(v *SessionView) { v.Factors = []string{"pwd", "totp"} },
		"amr":      func(v *SessionView) { v.AMR = nil },
		"remember": func(v *SessionView) { v.RememberMe = false },
		"return":   func(v *SessionView) { v.ReturnTo = "" },
		"change":   func(v *SessionView) { v.PasswordChangeRequired = true },
	} {
		other := base
		mutate(&other)
		require.False(t, equalViews(base, other), name)
	}
}

func TestMatrixCarrierAssertionAcceptsTheMatchingWorld(t *testing.T) {
	for _, cell := range []Cell{
		{Primary: PrimaryPassword, MFA: MFANone, Backend: JWT, Carrier: Cookies, Tenancy: Single},
		{Primary: PrimaryPassword, MFA: MFANone, Backend: Stateful, Carrier: Cookies, Tenancy: Single},
		{Primary: PrimaryPassword, MFA: MFANone, Backend: JWT, Carrier: Bearer, Tenancy: Single},
		{Primary: PrimaryPassword, MFA: MFANone, Backend: Stateful, Carrier: Bearer, Tenancy: Single},
	} {
		r, c := carrierRun(t, cell, cell.Settings(), cell.Carrier == Bearer)
		msg, failed := fatalOf(func() { r.assertCarrier(c) })
		require.False(t, failed, "%s: %s", cell, msg)
	}
}

func TestMatrixCarrierAssertionCatchesAConfigTransportThatIsIgnored(t *testing.T) {
	bearerCell := Cell{Primary: PrimaryPassword, MFA: MFANone, Backend: JWT, Carrier: Bearer, Tenancy: Single}
	cookiesWorld := Settings{Backend: JWT, Tenancy: Single, Transport: egauth.Cookies}
	r, c := carrierRun(t, bearerCell, cookiesWorld, false)
	_, failed := fatalOf(func() { r.assertCarrier(c) })
	require.True(t, failed, "a Bearer cell served by cookies must fail")

	cookiesCell := bearerCell
	cookiesCell.Carrier = Cookies
	bearerWorld := Settings{Backend: JWT, Tenancy: Single, Transport: egauth.Bearer}
	r, c = carrierRun(t, cookiesCell, bearerWorld, true)
	_, failed = fatalOf(func() { r.assertCarrier(c) })
	require.True(t, failed, "a cookies cell exposing a token must fail")
}

func TestMatrixCarrierAssertionCatchesTheWrongBackend(t *testing.T) {
	cell := Cell{Primary: PrimaryPassword, MFA: MFANone, Backend: JWT, Carrier: Cookies, Tenancy: Single}
	r, c := carrierRun(t, cell, Settings{Backend: Stateful, Tenancy: Single, Transport: egauth.Cookies}, false)
	_, failed := fatalOf(func() { r.assertCarrier(c) })
	require.True(t, failed, "a JWT cell served by the stateful backend must fail")

	cell.Carrier = Bearer
	r, c = carrierRun(t, cell, Settings{Backend: Stateful, Tenancy: Single, Transport: egauth.Bearer}, true)
	_, failed = fatalOf(func() { r.assertCarrier(c) })
	require.True(t, failed, "a JWT Bearer cell holding an opaque token must fail")
}

func TestMatrixSessionDecodingRequiresEveryMember(t *testing.T) {
	full := `{"subject":"s","tenant":"","factors":["pwd"],"amr":["pwd"],"remember_me":false,"return_to":"/app","password_change_required":false}`
	_, failed := fatalOf(func() { decodeSession(fatalRecorder{TB: t}, &Resp{Body: []byte(full)}) })
	require.False(t, failed)
	for _, member := range sessionMembers {
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(full), &body))
		delete(body, member)
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		msg, failed := fatalOf(func() { decodeSession(fatalRecorder{TB: t}, &Resp{Body: raw}) })
		require.True(t, failed, "a body without %q must fail", member)
		require.Contains(t, msg, member)
	}
}

func TestMatrixRememberMeTakesBothValuesForEveryPrimary(t *testing.T) {
	seen := map[Primary]map[bool]bool{}
	for _, c := range FullMatrix() {
		if seen[c.Primary] == nil {
			seen[c.Primary] = map[bool]bool{}
		}
		seen[c.Primary][rememberFor(c)] = true
	}
	for _, p := range Primaries() {
		require.Len(t, seen[p], 2, "primary %s is only ever run with one remember-me value", p)
	}
}

func TestMatrixCreatingSignInIsMeasuredWithItsCreationEvents(t *testing.T) {
	oauth, _ := primaryDriverOf(PrimaryOAuthOIDC)
	require.NotEmpty(t, oauth.CreateEvents)
	want := append(append([]event.Type{}, oauth.CreateEvents...), event.SessionIssued, event.LoginSucceeded)
	require.Equal(t, want, expectedEvents(oauth, SecondDriver{}, false, true))
	require.Equal(t, []event.Type{event.SessionIssued, event.LoginSucceeded}, expectedEvents(oauth, SecondDriver{}, false, false))
}
