package egauth

import "github.com/JLugagne/egauth/internal/routes"

// Endpoint paths, relative to the configured base path. Parameterised segments use {name}.
const (
	PathSession                    = routes.Session
	PathLogout                     = routes.Logout
	PathLogoutEverywhere           = routes.LogoutEverywhere
	PathReauth                     = routes.Reauth
	PathRefresh                    = routes.Refresh
	PathExchange                   = routes.Exchange
	PathResourceToken              = routes.ResourceToken
	PathSecurityRevert             = routes.SecurityRevert
	PathJWKS                       = routes.JWKS
	PathRegister                   = routes.Register
	PathRegisterConfirm            = routes.RegisterConfirm
	PathLogin                      = routes.Login
	PathPasswordForgot             = routes.PasswordForgot
	PathPasswordReset              = routes.PasswordReset
	PathPasswordChange             = routes.PasswordChange
	PathMagicLinkRequest           = routes.MagicLinkRequest
	PathMagicLink                  = routes.MagicLink
	PathCodeRequest                = routes.CodeRequest
	PathCodeVerify                 = routes.CodeVerify
	PathPasskeyLoginBegin          = routes.PasskeyLoginBegin
	PathPasskeyLoginFinish         = routes.PasskeyLoginFinish
	PathPasskeyRegisterBegin       = routes.PasskeyRegisterBegin
	PathPasskeyRegisterFinish      = routes.PasskeyRegisterFinish
	PathPasskeyCredentials         = routes.PasskeyCredentials
	PathPasskeyCredentialsRename   = routes.PasskeyCredentialsRename
	PathPasskeyCredentialsDelete   = routes.PasskeyCredentialsDelete
	PathOAuthBegin                 = routes.OAuthBegin
	PathOAuthCallback              = routes.OAuthCallback
	PathOAuthLink                  = routes.OAuthLink
	PathExternalLogin              = routes.ExternalLogin
	PathMFAChallenge               = routes.MFAChallenge
	PathMFAPasskeyBegin            = routes.MFAPasskeyBegin
	PathMFAPasskeyFinish           = routes.MFAPasskeyFinish
	PathMFATOTPEnroll              = routes.MFATOTPEnroll
	PathMFATOTPConfirm             = routes.MFATOTPConfirm
	PathMFATOTPDisable             = routes.MFATOTPDisable
	PathMFARecoveryCodesRegenerate = routes.MFARecoveryCodesRegenerate
	PathEmailVerifyRequest         = routes.EmailVerifyRequest
	PathEmailVerify                = routes.EmailVerify
	PathEmailChange                = routes.EmailChange
	PathEmailChangeConfirm         = routes.EmailChangeConfirm
	PathPhoneVerifyRequest         = routes.PhoneVerifyRequest
	PathPhoneVerify                = routes.PhoneVerify
	PathRecoveryEmail              = routes.RecoveryEmail
	PathRecoveryEmailConfirm       = routes.RecoveryEmailConfirm
	PathAccountDelete              = routes.AccountDelete
)

// PathWellKnown is the discovery document path, served at the host root outside the base path.
const PathWellKnown = routes.WellKnown

// Request field names accepted by the endpoints; any other form or JSON field is ignored.
const (
	FieldIdentifier   = routes.FieldIdentifier
	FieldPassword     = routes.FieldPassword
	FieldNewPassword  = routes.FieldNewPassword
	FieldRemember     = routes.FieldRemember
	FieldReturnTo     = routes.FieldReturnTo
	FieldCode         = routes.FieldCode
	FieldFactor       = routes.FieldFactor
	FieldEmail        = routes.FieldEmail
	FieldPhone        = routes.FieldPhone
	FieldToken        = routes.FieldToken
	FieldFlow         = routes.FieldFlow
	FieldHandle       = routes.FieldHandle
	FieldBind         = routes.FieldBind
	FieldCredentialID = routes.FieldCredentialID
	FieldNickname     = routes.FieldNickname
	FieldConfirm      = routes.FieldConfirm
	FieldCaptchaToken = routes.FieldCaptchaToken
	FieldResource     = routes.FieldResource
)

// HeaderTransport selects Bearer transport on a login request, when the configuration allows it.
const HeaderTransport = routes.HeaderTransport
