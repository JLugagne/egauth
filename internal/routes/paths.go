// Package routes holds the closed registry of endpoint paths, request field names and header names.
package routes

import "net/http"

// Paths relative to BasePath. Parameterised segments use {name}.
const (
	Session                    = "/session"
	Logout                     = "/logout"
	LogoutEverywhere           = "/logout-everywhere"
	Reauth                     = "/reauth"
	Refresh                    = "/refresh"
	Exchange                   = "/exchange"
	ResourceToken              = "/resource-token"
	SecurityRevert             = "/security/revert"
	JWKS                       = "/jwks.json"
	Register                   = "/register"
	RegisterConfirm            = "/register/confirm"
	Login                      = "/login"
	PasswordForgot             = "/password/forgot"
	PasswordReset              = "/password/reset"
	PasswordChange             = "/password/change"
	MagicLinkRequest           = "/magic-link/request"
	MagicLink                  = "/magic-link"
	CodeRequest                = "/code/request"
	CodeVerify                 = "/code/verify"
	PasskeyLoginBegin          = "/passkey/login/begin"
	PasskeyLoginFinish         = "/passkey/login/finish"
	PasskeyRegisterBegin       = "/passkey/register/begin"
	PasskeyRegisterFinish      = "/passkey/register/finish"
	PasskeyCredentials         = "/passkey/credentials"
	PasskeyCredentialsRename   = "/passkey/credentials/rename"
	PasskeyCredentialsDelete   = "/passkey/credentials/delete"
	OAuthBegin                 = "/oauth/{provider}/begin"
	OAuthCallback              = "/oauth/{provider}/callback"
	OAuthLink                  = "/oauth/{provider}/link"
	ExternalLogin              = "/external/{name}/login"
	MFAChallenge               = "/mfa/challenge"
	MFAPasskeyBegin            = "/mfa/passkey/begin"
	MFAPasskeyFinish           = "/mfa/passkey/finish"
	MFATOTPEnroll              = "/mfa/totp/enroll"
	MFATOTPConfirm             = "/mfa/totp/confirm"
	MFATOTPDisable             = "/mfa/totp/disable"
	MFARecoveryCodesRegenerate = "/mfa/recovery-codes/regenerate"
	EmailVerifyRequest         = "/email/verify/request"
	EmailVerify                = "/email/verify"
	EmailChange                = "/email/change"
	EmailChangeConfirm         = "/email/change/confirm"
	PhoneVerifyRequest         = "/phone/verify/request"
	PhoneVerify                = "/phone/verify"
	RecoveryEmail              = "/recovery-email"
	RecoveryEmailConfirm       = "/recovery-email/confirm"
	AccountDelete              = "/account/delete"
)

// WellKnown is the discovery document path; it is served at the host root, outside BasePath.
const WellKnown = "/.well-known/egauth-configuration"

// Method returns the HTTP method of the endpoint at path, or "" when path is not registered.
func Method(path string) string {
	switch path {
	case Session, JWKS, PasskeyCredentials, OAuthBegin, OAuthCallback:
		return http.MethodGet
	case Logout, LogoutEverywhere, Reauth, Refresh, Exchange, ResourceToken, SecurityRevert, Register, RegisterConfirm, Login, PasswordForgot, PasswordReset, PasswordChange, MagicLinkRequest, MagicLink, CodeRequest, CodeVerify, PasskeyLoginBegin, PasskeyLoginFinish, PasskeyRegisterBegin, PasskeyRegisterFinish, PasskeyCredentialsRename, PasskeyCredentialsDelete, OAuthLink, ExternalLogin, MFAChallenge, MFAPasskeyBegin, MFAPasskeyFinish, MFATOTPEnroll, MFATOTPConfirm, MFATOTPDisable, MFARecoveryCodesRegenerate, EmailVerifyRequest, EmailVerify, EmailChange, EmailChangeConfirm, PhoneVerifyRequest, PhoneVerify, RecoveryEmail, RecoveryEmailConfirm, AccountDelete:
		return http.MethodPost
	}
	return ""
}

// All returns every registered endpoint path relative to BasePath.
func All() []string {
	return []string{
		Session,
		Logout,
		LogoutEverywhere,
		Reauth,
		Refresh,
		Exchange,
		ResourceToken,
		SecurityRevert,
		JWKS,
		Register,
		RegisterConfirm,
		Login,
		PasswordForgot,
		PasswordReset,
		PasswordChange,
		MagicLinkRequest,
		MagicLink,
		CodeRequest,
		CodeVerify,
		PasskeyLoginBegin,
		PasskeyLoginFinish,
		PasskeyRegisterBegin,
		PasskeyRegisterFinish,
		PasskeyCredentials,
		PasskeyCredentialsRename,
		PasskeyCredentialsDelete,
		OAuthBegin,
		OAuthCallback,
		OAuthLink,
		ExternalLogin,
		MFAChallenge,
		MFAPasskeyBegin,
		MFAPasskeyFinish,
		MFATOTPEnroll,
		MFATOTPConfirm,
		MFATOTPDisable,
		MFARecoveryCodesRegenerate,
		EmailVerifyRequest,
		EmailVerify,
		EmailChange,
		EmailChangeConfirm,
		PhoneVerifyRequest,
		PhoneVerify,
		RecoveryEmail,
		RecoveryEmailConfirm,
		AccountDelete,
	}
}

// Request field names; a field outside this set is ignored and never echoed.
const (
	FieldIdentifier   = "identifier"
	FieldPassword     = "password"
	FieldNewPassword  = "new_password"
	FieldRemember     = "remember"
	FieldReturnTo     = "return_to"
	FieldCode         = "code"
	FieldFactor       = "factor"
	FieldEmail        = "email"
	FieldPhone        = "phone"
	FieldToken        = "token"
	FieldFlow         = "flow"
	FieldHandle       = "handle"
	FieldBind         = "bind"
	FieldCredentialID = "credential_id"
	FieldNickname     = "nickname"
	FieldConfirm      = "confirm"
	FieldCaptchaToken = "captcha_token"
	FieldResource     = "resource"
)

// Fields returns a fresh copy of the closed request field set; the caller may modify it.
func Fields() []string {
	return []string{
		FieldIdentifier,
		FieldPassword,
		FieldNewPassword,
		FieldRemember,
		FieldReturnTo,
		FieldCode,
		FieldFactor,
		FieldEmail,
		FieldPhone,
		FieldToken,
		FieldFlow,
		FieldHandle,
		FieldBind,
		FieldCredentialID,
		FieldNickname,
		FieldConfirm,
		FieldCaptchaToken,
		FieldResource,
	}
}

// HeaderTransport selects Bearer transport on a login request when the configuration allows it.
const HeaderTransport = "X-Egauth-Transport"
