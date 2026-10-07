// Package ceremony holds the closed registry of ceremony kinds and, in later files, the ceremony
// store contract. Lifetimes, caps and attempt bounds are library constants on Kind; no call site
// passes them.
package ceremony

import "time"

const pendingTTL = 15 * time.Minute

// Kind identifies one short-lived artefact. Its numeric value is persisted (egauth_ceremonies.kind),
// so a value is never renumbered or reused; a new kind takes the next free number. The zero Kind is
// invalid and fails closed: it has no lifetime and no capacity.
type Kind uint8

const (
	// MFAFlow parks a login whose primary factor is verified until the second factor is.
	MFAFlow Kind = 1
	// PasskeyRegistration holds the WebAuthn creation challenge of a passkey enrollment.
	PasskeyRegistration Kind = 2
	// MFAPasskey holds the WebAuthn assertion challenge of a passkey used as second factor
	// (pk_stepup).
	MFAPasskey Kind = 3
	// MagicLink is an emailed sign-in link; consuming it yields the email_link factor.
	MagicLink Kind = 4
	// EmailCode is an emailed sign-in code (EmailDeliverer.LoginCode); verifying it yields the
	// email_code factor. A texted sign-in code is SMSCode, never EmailCode.
	EmailCode Kind = 5
	// SMSCode is a texted sign-in code (SMSDeliverer.LoginCode); verifying it yields the sms_code
	// factor.
	SMSCode Kind = 6
	// PhoneVerification is a texted code proving that a subject owns a phone number; it yields no
	// factor.
	PhoneVerification Kind = 7
	// PasswordReset is an emailed reset link (EmailDeliverer.PasswordResetLink); it never admits a
	// session.
	PasswordReset Kind = 8
	// PendingRegistration is an emailed registration link; consuming it creates a verified account
	// and admits it with the email_link factor.
	PendingRegistration Kind = 9
	// EmailVerification is an emailed link proving that a subject owns its email; it yields no factor.
	EmailVerification Kind = 10
	// EmailChange is a link sent to the new address that confirms an email change.
	EmailChange Kind = 11
	// RecoveryEmail is a link sent to a recovery address that confirms it.
	RecoveryEmail Kind = 12
	// SecurityRevert is the revert link of a security notice, bound to and capped by the address
	// that received it, so notices sent to a later address never evict it (C-45); it never admits a
	// session.
	SecurityRevert Kind = 13
	// Exchange redeems the browser leg of an OAuth login under Bearer transport.
	Exchange Kind = 14
	// DiscoverablePasskey is the stateless begin of a usernameless passkey login (pk).
	DiscoverablePasskey Kind = 15
	// UsernameFirstPasskey is the stateless begin of a passkey login for a typed identifier (pk).
	UsernameFirstPasskey Kind = 16
	// OAuthState is the stateless begin of a federated login (fed).
	OAuthState Kind = 17
	// ExternalLogin is the stateless begin of an integrator-provided login (ext).
	ExternalLogin Kind = 18
	// PasswordResetCode is a texted reset code (SMSDeliverer.PasswordResetCode); it never admits a
	// session and is never accepted as a sign-in code.
	PasswordResetCode Kind = 19
	kindEnd           Kind = 20
)

// ScopeClass tells what a kind's records are grouped and capped by.
type ScopeClass uint8

const (
	// Subject scope groups records by the owning subject id.
	Subject ScopeClass = iota + 1
	// Identifier scope groups records by the keyed hash of a normalised identifier.
	Identifier
	// Anonymous kinds have no scope; they are stateless handles.
	Anonymous
)

// SecretClass tells how a handle must be generated and looked up.
type SecretClass uint8

const (
	// HighEntropy handles are 256-bit random or AEAD-sealed values and may be used as lookup keys.
	HighEntropy SecretClass = iota + 1
	// ShortCode kinds carry a human-typed code that is never a key; the lookup key is a separate
	// 256-bit handle and the code is compared in constant time against the payload.
	ShortCode
)

// All returns every valid kind in numeric order.
func All() []Kind {
	out := make([]Kind, 0, int(kindEnd)-1)
	for k := Kind(1); k < kindEnd; k++ {
		out = append(out, k)
	}
	return out
}

// Valid reports whether k is declared; an invalid kind has no lifetime, capacity or attempts.
func (k Kind) Valid() bool { return k >= 1 && k < kindEnd }

// Stateless reports whether the kind is an anonymous begin carried by a sealed handle and never
// stored as a row.
func (k Kind) Stateless() bool { return k.Scope() == Anonymous }

// String returns the snake_case name of k, or "invalid".
func (k Kind) String() string {
	switch k {
	case MFAFlow:
		return "mfa_flow"
	case PasskeyRegistration:
		return "passkey_registration"
	case MFAPasskey:
		return "mfa_passkey"
	case MagicLink:
		return "magic_link"
	case EmailCode:
		return "email_code"
	case SMSCode:
		return "sms_code"
	case PhoneVerification:
		return "phone_verification"
	case PasswordReset:
		return "password_reset"
	case PendingRegistration:
		return "pending_registration"
	case EmailVerification:
		return "email_verification"
	case EmailChange:
		return "email_change"
	case RecoveryEmail:
		return "recovery_email"
	case SecurityRevert:
		return "security_revert"
	case Exchange:
		return "exchange"
	case DiscoverablePasskey:
		return "discoverable_passkey"
	case UsernameFirstPasskey:
		return "username_first_passkey"
	case OAuthState:
		return "oauth_state"
	case ExternalLogin:
		return "external_login"
	case PasswordResetCode:
		return "password_reset_code"
	}
	return "invalid"
}

// AdmitsSession reports whether consuming the kind feeds its sealed Pending to Add or Admit. Such a
// kind's artefacts expire at ExpiresAt, never after their Pending, and a primary step's TTL leaves
// room for the Exchange and MFA flow that may follow it within the 15-minute Pending lifetime.
func (k Kind) AdmitsSession() bool {
	switch k {
	case MFAFlow, MFAPasskey, MagicLink, EmailCode, SMSCode, PendingRegistration,
		Exchange, DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin:
		return true
	case PasskeyRegistration, PhoneVerification, PasswordReset, EmailVerification, EmailChange,
		RecoveryEmail, SecurityRevert, PasswordResetCode:
		return false
	}
	return false
}

// TTL is how long a record or stateless handle of this kind stays usable. Passkey kinds also use it
// as the WebAuthn timeout. An invalid kind has a zero TTL.
func (k Kind) TTL() time.Duration {
	switch k {
	case MFAFlow, PasskeyRegistration, MFAPasskey, DiscoverablePasskey, UsernameFirstPasskey, ExternalLogin:
		return 5 * time.Minute
	case PhoneVerification, PasswordResetCode:
		return 10 * time.Minute
	case MagicLink, EmailCode, SMSCode, PendingRegistration:
		return pendingTTL - MFAFlow.TTL()
	case OAuthState:
		return pendingTTL - Exchange.TTL() - MFAFlow.TTL()
	case PasswordReset, EmailChange, RecoveryEmail:
		return time.Hour
	case EmailVerification:
		return 24 * time.Hour
	case SecurityRevert:
		return 7 * 24 * time.Hour
	case Exchange:
		return time.Minute
	}
	return 0
}

// MaxLivePerScope is the number of live rows kept per (tenant, kind, scope); Put evicts the oldest
// beyond it. Stateless and invalid kinds have no rows, so the cap is zero.
func (k Kind) MaxLivePerScope() int {
	switch k {
	case MFAFlow, PasskeyRegistration, MFAPasskey, SecurityRevert, Exchange:
		return 5
	case MagicLink, EmailCode, SMSCode, PhoneVerification, PasswordReset, PendingRegistration,
		EmailVerification, EmailChange, RecoveryEmail, PasswordResetCode:
		return 3
	case DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin:
		return 0
	}
	return 0
}

// MaxLivePerTenant is the number of live rows kept per (tenant, kind) on top of MaxLivePerScope;
// Put evicts the oldest of the tenant beyond it. Zero means no ceiling; only PendingRegistration,
// which any unauthenticated client can create for any identifier, carries one.
func (k Kind) MaxLivePerTenant() int {
	switch k {
	case PendingRegistration:
		return 10_000
	case MFAFlow, PasskeyRegistration, MFAPasskey, MagicLink, EmailCode, SMSCode, PhoneVerification,
		PasswordReset, EmailVerification, EmailChange, RecoveryEmail, SecurityRevert, Exchange,
		DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin, PasswordResetCode:
		return 0
	}
	return 0
}

// MaxAttempts is the number of failed verifications charged to a stored record (RecordFailure)
// after which it is deleted. The bound is load-bearing only where a found record is checked against
// a typed secret: ShortCode kinds, MFAFlow and MFAPasskey. Other stored kinds fail by a lookup miss
// on a 256-bit handle, which charges no record, so their bound is a fail-safe ceiling. Stateless and
// invalid kinds have no row to charge and return zero.
func (k Kind) MaxAttempts() int {
	switch k {
	case EmailCode, SMSCode, PhoneVerification, MFAFlow, MFAPasskey, PasswordResetCode:
		return 5
	case PasskeyRegistration, MagicLink, PasswordReset, PendingRegistration, EmailVerification,
		EmailChange, RecoveryEmail, SecurityRevert, Exchange:
		return 3
	case DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin:
		return 0
	}
	return 0
}

// SecretClass tells how the kind's handle is produced and looked up. An invalid kind reports the
// zero SecretClass.
func (k Kind) SecretClass() SecretClass {
	switch k {
	case EmailCode, SMSCode, PhoneVerification, PasswordResetCode:
		return ShortCode
	case MFAFlow, PasskeyRegistration, MFAPasskey, MagicLink, PasswordReset, PendingRegistration,
		EmailVerification, EmailChange, RecoveryEmail, SecurityRevert, Exchange,
		DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin:
		return HighEntropy
	}
	return 0
}

// Scope tells what the kind's rows are capped by. SecurityRevert is Identifier-scoped by the HMAC of
// the address the notice was sent to, not by subject. An invalid kind reports the zero ScopeClass.
func (k Kind) Scope() ScopeClass {
	switch k {
	case MFAFlow, PasskeyRegistration, MFAPasskey, PhoneVerification, PasswordReset,
		EmailVerification, EmailChange, RecoveryEmail, Exchange, PasswordResetCode:
		return Subject
	case MagicLink, EmailCode, SMSCode, PendingRegistration, SecurityRevert:
		return Identifier
	case DiscoverablePasskey, UsernameFirstPasskey, OAuthState, ExternalLogin:
		return Anonymous
	}
	return 0
}

// ExpiresAt is when an artefact of kind k created at now stops being usable; pendingEnd is the
// expiry of the Pending it seals. For a session-admitting kind the result is clamped to pendingEnd,
// so no live record or stateless handle ever carries an expired Pending, even at the end of a chain
// such as magic link, MFA flow, MFA passkey; a zero pendingEnd therefore yields an already expired
// artefact. ceremony.NewRecord and the stateless handle seal must use it instead of now+TTL. An
// invalid kind returns the zero time.
func (k Kind) ExpiresAt(pendingEnd, now time.Time) time.Time {
	if !k.Valid() {
		return time.Time{}
	}
	end := now.Add(k.TTL())
	if k.AdmitsSession() && pendingEnd.Before(end) {
		return pendingEnd
	}
	return end
}
