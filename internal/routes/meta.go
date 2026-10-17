package routes

import (
	"net/http"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/limiter"
)

// EndpointMeta is the gate metadata of an auth endpoint (DESIGN §3.9). The type lives in httpx so
// that the preamble can enforce it without importing this package.
type EndpointMeta = httpx.Meta

// MetaFor computes the metadata of the endpoint at path from the closed path registry; it reports
// false for an unregistered path. It is the only source of EndpointMeta: Table refuses an Endpoint
// whose Meta differs.
//
// EndsSession is set on /logout and /logout-everywhere only: they revoke and never issue, so a
// native client's Authorization Bearer credential selects Bearer transport there.
//
// Sensitive endpoints need an established session that is MultiFactor when enrolled and fresh
// within ReauthWindow. /logout-everywhere is deliberately not sensitive (C-71): a protective action
// must not be blocked; it stays authenticated and rate-limited. Authenticated actions that verify
// no guessable secret are limited per session lineage rather than per client address, so a
// neighbour behind the same NAT cannot exhaust them with login attempts.
func MetaFor(path string) (EndpointMeta, bool) {
	method := Method(path)
	if method == "" {
		return EndpointMeta{}, false
	}
	m := EndpointMeta{
		Authenticated:     authenticated(path),
		Mutation:          method == http.MethodPost,
		Sensitive:         sensitive(path),
		AcceptsMustChange: acceptsMustChange(path),
		SetsCookies:       setsCookies(path, method),
		EndsSession:       path == Logout || path == LogoutEverywhere,
		BodyCap:           httpx.FormBodyCap,
		ClientLimit:       clientLimit(path, method),
		IdentifierLimit:   identifierLimit(path),
	}
	if sessionAction(path) {
		m.ClientLimit, m.SessionLimit = 0, limiter.LoginClient
	}
	m.IdentifierKeyed = m.IdentifierLimit != 0
	if webAuthn(path) {
		m.BodyCap = httpx.WebAuthnBodyCap
	}
	return m, true
}

func authenticated(path string) bool {
	switch path {
	case Session, LogoutEverywhere, Reauth, ResourceToken, PasswordChange,
		PasskeyRegisterBegin, PasskeyRegisterFinish, PasskeyCredentials, PasskeyCredentialsRename, PasskeyCredentialsDelete,
		OAuthLink, MFATOTPEnroll, MFATOTPConfirm, MFATOTPDisable, MFARecoveryCodesRegenerate,
		EmailChange, PhoneVerifyRequest, PhoneVerify, RecoveryEmail, AccountDelete:
		return true
	}
	return false
}

func sensitive(path string) bool {
	switch path {
	case PasswordChange, EmailChange, PhoneVerifyRequest, RecoveryEmail,
		PasskeyRegisterBegin, PasskeyRegisterFinish, PasskeyCredentialsRename, PasskeyCredentialsDelete,
		MFATOTPEnroll, MFATOTPConfirm, MFATOTPDisable, MFARecoveryCodesRegenerate,
		AccountDelete, OAuthLink:
		return true
	}
	return false
}

func acceptsMustChange(path string) bool {
	switch path {
	case PasswordChange, Logout, LogoutEverywhere, Session, Reauth:
		return true
	}
	return false
}

func setsCookies(path, method string) bool {
	switch path {
	case Refresh, Exchange:
		return false
	case OAuthBegin, OAuthCallback:
		return true
	}
	return method == http.MethodPost
}

func sessionAction(path string) bool {
	switch path {
	case LogoutEverywhere, PasskeyCredentialsRename, PasskeyCredentialsDelete, PasskeyRegisterBegin, PasskeyRegisterFinish,
		OAuthLink, MFATOTPEnroll, MFARecoveryCodesRegenerate:
		return true
	}
	return false
}

func webAuthn(path string) bool {
	switch path {
	case PasskeyLoginFinish, PasskeyRegisterFinish, MFAPasskeyFinish, Reauth:
		return true
	}
	return false
}

func identifierLimit(path string) limiter.Class {
	switch path {
	case Login, PasskeyLoginBegin, ExternalLogin:
		return limiter.LoginIdentifier
	case Register, PasswordForgot, MagicLinkRequest, CodeRequest, EmailVerifyRequest:
		return limiter.CodeRequestIdentifier
	}
	return 0
}

func clientLimit(path, method string) limiter.Class {
	switch path {
	case Register:
		return limiter.RegisterClient
	case PasswordForgot, MagicLinkRequest, CodeRequest, EmailVerifyRequest, PhoneVerifyRequest, EmailChange, RecoveryEmail:
		return limiter.CodeRequestClient
	case Logout, Refresh, ResourceToken:
		return 0
	case OAuthBegin, OAuthCallback:
		return limiter.LoginClient
	}
	if method == http.MethodPost {
		return limiter.LoginClient
	}
	return 0
}
