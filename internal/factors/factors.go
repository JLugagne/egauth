// Package factors is the only builder of core.Verified. Each ceremony has one constructor, which
// fixes the factor codes, the identifying flag and the credential rules, so a handler cannot
// stamp a factor it did not verify (I-18).
package factors

import (
	"errors"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/core"
)

// ExternalProviderPrefix prefixes the provider name of an external primary factor.
const ExternalProviderPrefix = "external:"

var (
	// ErrUserVerificationRequired is returned for a passkey assertion without user verification;
	// every passkey ceremony requires it (C-28).
	ErrUserVerificationRequired = errors.New("factors: passkey user verification required")
	// ErrUserPresenceRequired is returned for a passkey assertion without user presence.
	ErrUserPresenceRequired = errors.New("factors: passkey user presence required")
	// ErrCredentialSuspended is returned for a suspended passkey credential (P-12).
	ErrCredentialSuspended = errors.New("factors: passkey credential suspended")
	// ErrMissingCredentialID is returned for a passkey credential without an id.
	ErrMissingCredentialID = errors.New("factors: passkey credential id missing")
	// ErrMissingProvider is returned for a federated or external factor without a provider name.
	ErrMissingProvider = errors.New("factors: provider name missing")
	// ErrReservedProvider is returned for a federated provider name starting with
	// ExternalProviderPrefix, which would make it indistinguishable from an external factor.
	ErrReservedProvider = errors.New("factors: provider name uses the external prefix")
)

// AuthenticatorFlags are the WebAuthn authenticator-data flags of a verified assertion.
type AuthenticatorFlags struct {
	UserPresent  bool
	UserVerified bool
}

// PasskeyCredential is the stored credential an assertion was verified against.
type PasskeyCredential struct {
	Owner     core.Subject
	ID        []byte
	Suspended bool
}

// Password records a password verified for an identifier that resolved to s.
func Password(s core.Subject, at time.Time) (core.Verified, error) {
	return primary(s, core.FactorPassword, at)
}

// EmailLink records a magic link consumed by s. Its AMR is "email", never "otp" (I-18).
func EmailLink(s core.Subject, at time.Time) (core.Verified, error) {
	return primary(s, core.FactorEmailLink, at)
}

// EmailCode records a one-time code delivered by email and entered by s.
func EmailCode(s core.Subject, at time.Time) (core.Verified, error) {
	return primary(s, core.FactorEmailCode, at)
}

// SMSCode records a one-time code delivered by SMS and entered by s.
func SMSCode(s core.Subject, at time.Time) (core.Verified, error) {
	return primary(s, core.FactorSMSCode, at)
}

// Federated records a federated login of s through provider. It returns ErrMissingProvider for
// an empty provider and ErrReservedProvider for one starting with ExternalProviderPrefix.
func Federated(s core.Subject, provider string, at time.Time) (core.Verified, error) {
	if provider == "" {
		return core.Verified{}, ErrMissingProvider
	}
	if strings.HasPrefix(provider, ExternalProviderPrefix) {
		return core.Verified{}, ErrReservedProvider
	}
	return core.NewVerified(core.VerifiedSpec{
		Subject: s, Factors: []core.Factor{core.FactorFederated}, Identifies: true, Provider: provider, At: at,
	})
}

// External records a login of s through the external factor named name; the recorded provider
// is ExternalProviderPrefix + name. It returns ErrMissingProvider for an empty name.
func External(s core.Subject, name string, at time.Time) (core.Verified, error) {
	if name == "" {
		return core.Verified{}, ErrMissingProvider
	}
	return core.NewVerified(core.VerifiedSpec{
		Subject: s, Factors: []core.Factor{core.FactorExternal}, Identifies: true, Provider: ExternalProviderPrefix + name, At: at,
	})
}

// Passkey records a primary passkey assertion against cred. It yields pk and uv. It returns
// ErrUserPresenceRequired, ErrUserVerificationRequired, ErrCredentialSuspended or
// ErrMissingCredentialID.
func Passkey(cred PasskeyCredential, flags AuthenticatorFlags, at time.Time) (core.Verified, error) {
	if err := checkPasskey(cred, flags); err != nil {
		return core.Verified{}, err
	}
	return core.NewVerified(core.VerifiedSpec{
		Subject:      cred.Owner,
		Factors:      []core.Factor{core.FactorPasskey, core.FactorUserVerification},
		CredentialID: cred.ID,
		Identifies:   true,
		At:           at,
	})
}

// PasskeyStepUp records a passkey assertion used as a second factor. Pending.Add refuses it when
// cred is the credential of the primary passkey (C-28). It returns the errors of Passkey.
func PasskeyStepUp(cred PasskeyCredential, flags AuthenticatorFlags, at time.Time) (core.Verified, error) {
	if err := checkPasskey(cred, flags); err != nil {
		return core.Verified{}, err
	}
	return core.NewVerified(core.VerifiedSpec{
		Subject:      cred.Owner,
		Factors:      []core.Factor{core.FactorPasskeyStepUp},
		CredentialID: cred.ID,
		At:           at,
	})
}

// TOTP records a TOTP code verified for s. It never identifies a subject.
func TOTP(s core.Subject, at time.Time) (core.Verified, error) {
	return second(s, core.FactorTOTP, at)
}

// RecoveryCode records a recovery code consumed by s. It never identifies a subject.
func RecoveryCode(s core.Subject, at time.Time) (core.Verified, error) {
	return second(s, core.FactorRecoveryCode, at)
}

func primary(s core.Subject, f core.Factor, at time.Time) (core.Verified, error) {
	return core.NewVerified(core.VerifiedSpec{Subject: s, Factors: []core.Factor{f}, Identifies: true, At: at})
}

func second(s core.Subject, f core.Factor, at time.Time) (core.Verified, error) {
	return core.NewVerified(core.VerifiedSpec{Subject: s, Factors: []core.Factor{f}, At: at})
}

func checkPasskey(cred PasskeyCredential, flags AuthenticatorFlags) error {
	if !flags.UserPresent {
		return ErrUserPresenceRequired
	}
	if !flags.UserVerified {
		return ErrUserVerificationRequired
	}
	if cred.Suspended {
		return ErrCredentialSuspended
	}
	if len(cred.ID) == 0 {
		return ErrMissingCredentialID
	}
	return nil
}
