// Package testdata holds the golden production configuration of the journey suite. It is imported by
// path from internal/journeytest (the go tool skips testdata directories only for wildcard patterns).
package testdata

import (
	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/kek"
)

// Deps are the integrator-owned values of the golden configuration: everything a deployment brings
// that is not a library default. Every field is required except Hooks and SMS.
type Deps[C any] struct {
	Origin    string
	Tenancy   egauth.Tenancy
	Sessions  egauth.SessionBackend
	Transport egauth.Transport
	Audiences []string
	Storage   egauth.Storage
	KEK       kek.KEK
	Claims    egauth.ClaimsSource[C]
	Events    event.Sink
	Email     egauth.EmailDeliverer
	SMS       egauth.SMSDeliverer
	Providers []federation.Provider
	Verifiers []egauth.ExternalFactor
	AdminRole string
	APIKinds  []string
	Hooks     egauth.Hooks
}

// ProdConfig returns the golden production configuration: every module enabled, the library
// defaults for rate limiting, origins, session lifetimes and cookies, and no Insecure opt-out of any
// kind. Its Posture().OptOuts must stay empty; a configuration that needs an opt-out is not the
// golden one.
func ProdConfig[C any](d Deps[C]) egauth.Config[C] {
	return egauth.Config[C]{
		PublicOrigin: d.Origin,
		Audiences:    d.Audiences,
		Proxy:        egauth.DirectClients(),
		Tenancy:      d.Tenancy,
		Storage:      d.Storage,
		KEK:          d.KEK,
		Sessions:     d.Sessions,
		Transport:    d.Transport,
		Admin:        egauth.RoleAdmin(d.AdminRole),
		Claims:       d.Claims,
		Events:       d.Events,
		Email:        d.Email,
		SMS:          d.SMS,
		Pages: egauth.Pages{
			Login: "/login", AfterLogin: "/home", MFA: "/mfa", Reauth: "/reauth", Error: "/error",
			ConfirmRegistration: "/register/confirm", MagicLink: "/magic", PasswordReset: "/reset",
			VerifyEmail: "/verify", ConfirmEmailChange: "/email/confirm", SecurityRevert: "/revert",
		},
		Modules: egauth.Modules{
			Password:     &egauth.PasswordModule{},
			MagicLink:    &egauth.MagicLinkModule{},
			LoginCode:    &egauth.LoginCodeModule{Email: true, SMS: d.SMS != nil},
			Passkey:      &egauth.PasskeyModule{DisplayName: "journeytest"},
			OAuth:        &egauth.OAuthModule{Providers: d.Providers},
			External:     &egauth.ExternalModule{Verifiers: d.Verifiers},
			MFA:          &egauth.MFAModule{},
			Verification: &egauth.VerificationModule{Email: true, Phone: d.SMS != nil, RecoveryEmail: true},
			SelfDelete:   &egauth.SelfDeleteModule{},
			APIKeys:      &egauth.APIKeyModule{Kinds: d.APIKinds},
		},
		Hooks: d.Hooks,
	}
}
