// Package lifecycle defines the account lifecycle events and the Subscriber every component
// implements in full, so that each component decides every event.
package lifecycle

import (
	"context"

	"github.com/JLugagne/egauth/principal"
	"github.com/google/uuid"
)

// RotationReason tells why a credential was rotated. Its numeric value is persisted
// (egauth_epoch_log.reason), so a value is never renumbered or reused.
type RotationReason uint8

const (
	RotationPasswordChanged   RotationReason = 1
	RotationPasswordReset     RotationReason = 2
	RotationTemporaryPassword RotationReason = 3
	RotationSecurityRevert    RotationReason = 4
)

// String returns the snake_case name of r, or "invalid".
func (r RotationReason) String() string {
	switch r {
	case RotationPasswordChanged:
		return "password_changed"
	case RotationPasswordReset:
		return "password_reset"
	case RotationTemporaryPassword:
		return "temporary_password"
	case RotationSecurityRevert:
		return "security_revert"
	}
	return "invalid"
}

// FactorChange tells which second-factor, passkey or federation-link change happened. Its numeric
// value is persisted in the lifecycle outbox, so a value is never renumbered or reused.
type FactorChange uint8

const (
	FactorTOTPEnrolled             FactorChange = 1
	FactorTOTPDisabled             FactorChange = 2
	FactorRecoveryCodesRegenerated FactorChange = 3
	FactorPasskeyAdded             FactorChange = 4
	FactorPasskeyRemoved           FactorChange = 5
	// FactorFederatedLinked reports a new federated identity link (identity.LinkFederated); it
	// gets a notice and a revert link because a link added on a hijacked session persists access.
	FactorFederatedLinked FactorChange = 6
	// FactorFederatedUnlinked reports a removed federated identity link (identity.UnlinkFederated).
	FactorFederatedUnlinked FactorChange = 7
)

// String returns the snake_case name of c, or "invalid".
func (c FactorChange) String() string {
	switch c {
	case FactorTOTPEnrolled:
		return "totp_enrolled"
	case FactorTOTPDisabled:
		return "totp_disabled"
	case FactorRecoveryCodesRegenerated:
		return "recovery_codes_regenerated"
	case FactorPasskeyAdded:
		return "passkey_added"
	case FactorPasskeyRemoved:
		return "passkey_removed"
	case FactorFederatedLinked:
		return "federated_linked"
	case FactorFederatedUnlinked:
		return "federated_unlinked"
	}
	return "invalid"
}

// IdentifierKind tells which contact identifier changed. Its numeric value is persisted in the
// lifecycle outbox, so a value is never renumbered or reused.
type IdentifierKind uint8

const (
	IdentifierEmail         IdentifierKind = 1
	IdentifierPhone         IdentifierKind = 2
	IdentifierRecoveryEmail IdentifierKind = 3
)

// String returns the snake_case name of k, or "invalid".
func (k IdentifierKind) String() string {
	switch k {
	case IdentifierEmail:
		return "email"
	case IdentifierPhone:
		return "phone"
	case IdentifierRecoveryEmail:
		return "recovery_email"
	}
	return "invalid"
}

// CredentialRotated reports a password-class change; every session of the subject except Keep ends.
type CredentialRotated struct {
	Subject principal.Subject
	Keep    uuid.UUID
	Reason  RotationReason
}

// FactorsChanged reports a change to the subject's second factors, passkeys or federated links;
// every session except Keep ends.
type FactorsChanged struct {
	Subject principal.Subject
	Keep    uuid.UUID
	Change  FactorChange
}

// IdentifierChanged reports a change of contact identifier; Old is the previous value so the notice
// can reach the address that lost access.
type IdentifierChanged struct {
	Subject principal.Subject
	Kind    IdentifierKind
	Old     string
}

// AccountEvent carries the subject of a disable, enable or delete.
type AccountEvent struct{ Subject principal.Subject }

// TenantErased reports that every record of the tenant is being erased.
type TenantErased struct{ Tenant principal.TenantID }

// SessionEnded reports that one session family ended through logout, End or Reissue.
type SessionEnded struct {
	Subject principal.Subject
	Family  uuid.UUID
}

// Subscriber must be implemented in full by every component so that each one decides every event.
// Handlers run from the lifecycle outbox, are retried until they return nil and must be idempotent.
type Subscriber interface {
	OnCredentialRotated(ctx context.Context, e CredentialRotated) error
	OnFactorsChanged(ctx context.Context, e FactorsChanged) error
	OnIdentifierChanged(ctx context.Context, e IdentifierChanged) error
	OnDisabled(ctx context.Context, e AccountEvent) error
	OnEnabled(ctx context.Context, e AccountEvent) error
	OnDeleted(ctx context.Context, e AccountEvent) error
	OnTenantErased(ctx context.Context, e TenantErased) error
	OnSessionEnded(ctx context.Context, e SessionEnded) error
}
