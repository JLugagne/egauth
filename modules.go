package egauth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/passwords"
)

// Modules enables the auth features; a nil module is off. At least one primary module (Password,
// MagicLink, LoginCode with a channel, Passkey, OAuth or External) must be enabled.
type Modules struct {
	Password     *PasswordModule
	MagicLink    *MagicLinkModule
	LoginCode    *LoginCodeModule
	Passkey      *PasskeyModule
	OAuth        *OAuthModule
	External     *ExternalModule
	MFA          *MFAModule
	Verification *VerificationModule
	SelfDelete   *SelfDeleteModule
	APIKeys      *APIKeyModule
}

// PasswordModule enables password sign-in, registration through a verified email, and reset.
// Policy runs after the library floor (8 to 1024 characters after NFKC normalisation) and Breach.
type PasswordModule struct {
	Policy       passwords.Policy        `egauth:"default=password_policy"`
	Breach       passwords.BreachChecker `egauth:"optional"`
	Registration RegistrationMode        `egauth:"default=registration_open"`
}

// RegistrationMode says who may create an account. The zero value is invalid.
type RegistrationMode uint8

const (
	// RegistrationOpen lets anyone register; no account exists until the email is verified.
	RegistrationOpen RegistrationMode = iota + 1
	// RegistrationInviteOnly creates accounts only through the Accounts facade.
	RegistrationInviteOnly
)

func (m RegistrationMode) valid() bool {
	return m == RegistrationOpen || m == RegistrationInviteOnly
}

// MagicLinkModule enables sign-in through an emailed link.
type MagicLinkModule struct{}

// LoginCodeModule enables sign-in through a short code sent on the enabled channels; at least one
// must be enabled.
type LoginCodeModule struct {
	Email bool
	SMS   bool
}

// PasskeyModule enables WebAuthn passkeys. The relying party id is the host of PublicOrigin (the
// per-tenant host under TenantBySubdomain); New requires it to be a registrable domain and a suffix
// of every origin.
type PasskeyModule struct {
	DisplayName string            `egauth:"required,nonempty"`
	Attestation AttestationPolicy `egauth:"default=attestation_none"`
}

// AttestationPolicy is the attestation conveyance requested at passkey registration. The zero
// value is invalid.
type AttestationPolicy uint8

const (
	// AttestationNone requests no attestation statement, which keeps authenticator models private.
	AttestationNone AttestationPolicy = iota + 1
)

func (p AttestationPolicy) valid() bool {
	return p == AttestationNone
}

// OAuthModule enables federated sign-in. Providers are fixed at New; with PerTenant, tenants
// register their own providers at runtime through the Tenants facade. One of the two is needed.
type OAuthModule struct {
	Providers []federation.Provider `egauth:"optional,each=provider"`
	PerTenant bool
}

// ExternalModule enables application-verified primary factors.
type ExternalModule struct {
	Verifiers []ExternalFactor `egauth:"required,nonempty,each=external"`
}

// MFAModule enables TOTP and recovery-code enrollment and the passkey step-up. Enrollment is read
// from the stores, so a subject who enrolled a second factor is asked for it whatever the modules.
type MFAModule struct {
	TOTPIssuer string `egauth:"default=totp_issuer"`
}

// VerificationModule enables verification and change of the enabled contact channels; at least one
// must be enabled.
type VerificationModule struct{ Email, Phone, RecoveryEmail bool }

// SelfDeleteModule lets a user delete their own account.
type SelfDeleteModule struct{}

// APIKeyModule enables API keys of the declared kinds. Kinds are unique tokens; ProtectAPI accepts
// only these. Prefix, the visible lead of every issued key, is a token too.
type APIKeyModule struct {
	Kinds  []string `egauth:"required,nonempty,each=token"`
	Prefix string   `egauth:"default=api_key_prefix,token"`
}

func (m Modules) enabled() []string {
	var out []string
	for _, e := range []struct {
		name string
		on   bool
	}{
		{"Password", m.Password != nil}, {"MagicLink", m.MagicLink != nil}, {"LoginCode", m.LoginCode != nil},
		{"Passkey", m.Passkey != nil}, {"OAuth", m.OAuth != nil}, {"External", m.External != nil},
		{"MFA", m.MFA != nil}, {"Verification", m.Verification != nil}, {"SelfDelete", m.SelfDelete != nil},
		{"APIKeys", m.APIKeys != nil},
	} {
		if e.on {
			out = append(out, e.name)
		}
	}
	return out
}

// String lists the enabled modules by name; module settings are never formatted.
func (m Modules) String() string { return "Modules{" + strings.Join(m.enabled(), " ") + "}" }

// GoString renders m like String.
func (m Modules) GoString() string { return m.String() }

// Format renders m like String for every fmt verb, so no verb reaches module settings.
func (m Modules) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, m.String()) }

// MarshalJSON encodes the enabled module names only, like String.
func (m Modules) MarshalJSON() ([]byte, error) { return json.Marshal(m.enabled()) }

// LogValue renders m for slog like String.
func (m Modules) LogValue() slog.Value { return slog.StringValue(m.String()) }
