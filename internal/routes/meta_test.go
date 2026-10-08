package routes_test

import (
	"net/http"
	"slices"
	"sort"
	"testing"

	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/limiter"
)

func set(paths ...string) []string {
	out := slices.Clone(paths)
	sort.Strings(out)
	return out
}

func pathsWhere(pred func(routes.EndpointMeta) bool) []string {
	var out []string
	for _, p := range routes.All() {
		m, ok := routes.MetaFor(p)
		if ok && pred(m) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func TestSensitiveSetIsExactlyTheSpecSet(t *testing.T) {
	want := set(
		routes.PasswordChange, routes.EmailChange, routes.PhoneVerifyRequest, routes.RecoveryEmail,
		routes.PasskeyRegisterBegin, routes.PasskeyRegisterFinish, routes.PasskeyCredentialsRename, routes.PasskeyCredentialsDelete,
		routes.MFATOTPEnroll, routes.MFATOTPConfirm, routes.MFATOTPDisable, routes.MFARecoveryCodesRegenerate,
		routes.AccountDelete, routes.OAuthLink,
	)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.Sensitive }); !slices.Equal(got, want) {
		t.Fatalf("sensitive %v\nwant %v", got, want)
	}
}

func TestLogoutEverywhereIsAuthenticatedRateLimitedNotSensitive(t *testing.T) {
	m, ok := routes.MetaFor(routes.LogoutEverywhere)
	if !ok || m.Sensitive || !m.Authenticated || m.SessionLimit == 0 || !m.AcceptsMustChange {
		t.Fatalf("logout-everywhere meta %+v", m)
	}
}

func TestAcceptsMustChangeSetIsExactlyTheSpecSet(t *testing.T) {
	want := set(routes.PasswordChange, routes.Logout, routes.LogoutEverywhere, routes.Session, routes.Reauth)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.AcceptsMustChange }); !slices.Equal(got, want) {
		t.Fatalf("accepts must-change %v", got)
	}
}

func TestAuthenticatedSet(t *testing.T) {
	want := set(
		routes.Session, routes.LogoutEverywhere, routes.Reauth, routes.ResourceToken, routes.PasswordChange,
		routes.PasskeyRegisterBegin, routes.PasskeyRegisterFinish, routes.PasskeyCredentials,
		routes.PasskeyCredentialsRename, routes.PasskeyCredentialsDelete, routes.OAuthLink,
		routes.MFATOTPEnroll, routes.MFATOTPConfirm, routes.MFATOTPDisable, routes.MFARecoveryCodesRegenerate,
		routes.EmailChange, routes.PhoneVerifyRequest, routes.PhoneVerify, routes.RecoveryEmail, routes.AccountDelete,
	)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.Authenticated }); !slices.Equal(got, want) {
		t.Fatalf("authenticated %v", got)
	}
}

func TestIdentifierKeyedSet(t *testing.T) {
	login := set(routes.Login, routes.PasskeyLoginBegin)
	code := set(routes.Register, routes.PasswordForgot, routes.MagicLinkRequest, routes.CodeRequest, routes.EmailVerifyRequest)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.IdentifierLimit == limiter.LoginIdentifier }); !slices.Equal(got, login) {
		t.Fatalf("login identifier %v", got)
	}
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.IdentifierLimit == limiter.CodeRequestIdentifier }); !slices.Equal(got, code) {
		t.Fatalf("code identifier %v", got)
	}
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.IdentifierKeyed }); !slices.Equal(got, set(append(login, code...)...)) {
		t.Fatalf("identifier keyed %v", got)
	}
}

func TestEveryLoginTypeEndpointSetsCookies(t *testing.T) {
	for _, p := range []string{
		routes.Login, routes.Register, routes.RegisterConfirm, routes.MagicLinkRequest, routes.MagicLink,
		routes.CodeRequest, routes.CodeVerify, routes.PasskeyLoginBegin, routes.PasskeyLoginFinish,
		routes.ExternalLogin, routes.MFAChallenge, routes.MFAPasskeyBegin, routes.MFAPasskeyFinish, routes.Reauth,
		routes.OAuthBegin, routes.OAuthCallback, routes.Logout, routes.PasswordReset,
	} {
		if m, _ := routes.MetaFor(p); !m.SetsCookies {
			t.Errorf("%s does not set cookies", p)
		}
	}
	for _, p := range []string{routes.Refresh, routes.Exchange, routes.Session, routes.JWKS, routes.PasskeyCredentials} {
		if m, _ := routes.MetaFor(p); m.SetsCookies {
			t.Errorf("%s sets cookies", p)
		}
	}
}

func TestEveryMutationIsCheckedForCSRFWhenItCanSetCookies(t *testing.T) {
	for _, p := range routes.All() {
		m, _ := routes.MetaFor(p)
		if m.Mutation && !m.SetsCookies && p != routes.Refresh && p != routes.Exchange {
			t.Errorf("%s: unsafe endpoint escapes the no-cookie CSRF check", p)
		}
	}
}

func TestBodyCaps(t *testing.T) {
	webauthn := set(routes.PasskeyLoginFinish, routes.PasskeyRegisterFinish, routes.MFAPasskeyFinish)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.BodyCap == httpx.WebAuthnBodyCap }); !slices.Equal(got, webauthn) {
		t.Fatalf("WebAuthn caps %v", got)
	}
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.BodyCap == httpx.FormBodyCap }); len(got) != len(routes.All())-len(webauthn) {
		t.Fatalf("form caps %d", len(got))
	}
}

func TestEveryMetaIsEnforceableAndMutationMatchesMethod(t *testing.T) {
	for _, p := range routes.All() {
		m, ok := routes.MetaFor(p)
		if !ok {
			t.Fatalf("%s: no meta", p)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if m.Mutation != (routes.Method(p) == http.MethodPost) {
			t.Errorf("%s: mutation %v", p, m.Mutation)
		}
		if m.Sensitive && !m.Authenticated {
			t.Errorf("%s: sensitive but unauthenticated", p)
		}
	}
	if _, ok := routes.MetaFor("/nope"); ok {
		t.Fatal("unknown path has meta")
	}
}

func TestCredentialGuessingEndpointsAreClientLimited(t *testing.T) {
	for _, p := range []string{
		routes.Login, routes.Reauth, routes.CodeVerify, routes.MagicLink, routes.RegisterConfirm, routes.MFAChallenge,
		routes.MFAPasskeyFinish, routes.PasskeyLoginFinish, routes.ExternalLogin, routes.Exchange, routes.PasswordReset,
		routes.EmailVerify, routes.EmailChangeConfirm, routes.PhoneVerify, routes.RecoveryEmailConfirm, routes.SecurityRevert,
		routes.OAuthCallback, routes.MFATOTPConfirm, routes.MFATOTPDisable, routes.PasswordChange,
	} {
		if m, _ := routes.MetaFor(p); m.ClientLimit == 0 {
			t.Errorf("%s has no client limit", p)
		}
	}
}

func TestSessionActionsAreNotKeyedOnTheSharedClientBudget(t *testing.T) {
	for _, p := range []string{
		routes.LogoutEverywhere, routes.PasskeyCredentialsRename, routes.PasskeyCredentialsDelete,
		routes.PasskeyRegisterBegin, routes.PasskeyRegisterFinish, routes.OAuthLink,
		routes.MFATOTPEnroll, routes.MFARecoveryCodesRegenerate,
	} {
		m, _ := routes.MetaFor(p)
		if m.ClientLimit != 0 {
			t.Errorf("%s draws on the per-client budget a neighbour can drain", p)
		}
		if m.SessionLimit == 0 || m.Validate() != nil {
			t.Errorf("%s must stay rate-limited per session: %+v", p, m)
		}
	}
}

func TestMirrorsStayEqual(t *testing.T) {
	if !slices.Equal(httpx.FieldNames(), routes.Fields()) {
		t.Fatalf("httpx field set %v differs from routes %v", httpx.FieldNames(), routes.Fields())
	}
	if httpx.HeaderTransport != routes.HeaderTransport || csrf.HeaderTransport != routes.HeaderTransport {
		t.Fatal("transport header mirrors differ")
	}
}

func TestEndsSessionSetIsTheLogoutPair(t *testing.T) {
	want := set(routes.Logout, routes.LogoutEverywhere)
	if got := pathsWhere(func(m routes.EndpointMeta) bool { return m.EndsSession }); !slices.Equal(got, want) {
		t.Fatalf("ends session %v", got)
	}
}
