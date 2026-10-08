package identity

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

// Event is the lifecycle event an applied mutation queues in the outbox, and the reason of an epoch
// change. Its numeric value is persisted (egauth_lifecycle_outbox.event, egauth_epoch_log.reason),
// so a value is never renumbered or reused.
type Event uint8

const (
	EventCredentialRotated Event = 1
	EventFactorsChanged    Event = 2
	EventIdentifierChanged Event = 3
	EventDisable           Event = 4
	EventEnable            Event = 5
	EventDelete            Event = 6
	eventEnd               Event = 7
)

// Valid reports whether e is declared.
func (e Event) Valid() bool { return e >= EventCredentialRotated && e < eventEnd }

// String returns the snake_case name of e, or "invalid".
func (e Event) String() string {
	switch e {
	case EventCredentialRotated:
		return "credential_rotated"
	case EventFactorsChanged:
		return "factors_changed"
	case EventIdentifierChanged:
		return "identifier_changed"
	case EventDisable:
		return "disable"
	case EventEnable:
		return "enable"
	case EventDelete:
		return "delete"
	}
	return "invalid"
}

// RotationReason tells why SetPassword rotated the password. Its numeric value equals
// lifecycle.RotationReason's, so a value is never renumbered or reused.
type RotationReason uint8

const (
	RotationPasswordChanged   RotationReason = 1
	RotationPasswordReset     RotationReason = 2
	RotationTemporaryPassword RotationReason = 3
	RotationSecurityRevert    RotationReason = 4
)

// Valid reports whether r is declared.
func (r RotationReason) Valid() bool {
	return r >= RotationPasswordChanged && r <= RotationSecurityRevert
}

// ForcesChange reports whether a password set for this reason must be changed at next login;
// SetPassword stores exactly this as must_change.
func (r RotationReason) ForcesChange() bool { return r == RotationTemporaryPassword }

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

// FactorChange tells which factor or federated-link change bumped the epoch. Its numeric value
// equals lifecycle.FactorChange's, so a value is never renumbered or reused.
type FactorChange uint8

const (
	FactorTOTPEnrolled             FactorChange = 1
	FactorTOTPRemoved              FactorChange = 2
	FactorRecoveryCodesRegenerated FactorChange = 3
	FactorPasskeyAdded             FactorChange = 4
	FactorPasskeyRemoved           FactorChange = 5
	FactorFederatedLinked          FactorChange = 6
	FactorFederatedUnlinked        FactorChange = 7
)

// Valid reports whether c is declared.
func (c FactorChange) Valid() bool {
	return c >= FactorTOTPEnrolled && c <= FactorFederatedUnlinked
}

// String returns the snake_case name of c, as lifecycle.FactorChange spells it, or "invalid".
func (c FactorChange) String() string {
	switch c {
	case FactorTOTPEnrolled:
		return "totp_enrolled"
	case FactorTOTPRemoved:
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

// Component is one consumer of the lifecycle outbox, a row of the DESIGN §7.2 matrix. Apply writes
// one outbox row per component for every queued event, so each component decides every event and
// is retried on its own; a failing hook never replays a sent notice. Its name is persisted
// (egauth_lifecycle_outbox.subscriber), so a name is never changed or reused.
type Component uint8

const (
	ComponentSessions   Component = 1
	ComponentAPIKeys    Component = 2
	ComponentCeremonies Component = 3
	ComponentMFA        Component = 4
	ComponentPasskeys   Component = 5
	ComponentFederation Component = 6
	ComponentNotices    Component = 7
	ComponentKeys       Component = 8
	ComponentHooks      Component = 9
	// ComponentIdentity hard-deletes a tombstoned account; it runs once every other component of the
	// subject is done (EraseUser enforces it).
	ComponentIdentity Component = 10
	componentEnd      Component = 11
)

// Components returns every component in dispatch order, ComponentIdentity last.
func Components() []Component {
	out := make([]Component, 0, int(componentEnd)-1)
	for c := ComponentSessions; c < componentEnd; c++ {
		out = append(out, c)
	}
	return out
}

// Valid reports whether c is declared.
func (c Component) Valid() bool { return c >= ComponentSessions && c < componentEnd }

// String returns the persisted name of c, or "invalid".
func (c Component) String() string {
	switch c {
	case ComponentSessions:
		return "sessions"
	case ComponentAPIKeys:
		return "api_keys"
	case ComponentCeremonies:
		return "ceremonies"
	case ComponentMFA:
		return "mfa"
	case ComponentPasskeys:
		return "passkeys"
	case ComponentFederation:
		return "federation"
	case ComponentNotices:
		return "notices"
	case ComponentKeys:
		return "keys"
	case ComponentHooks:
		return "hooks"
	case ComponentIdentity:
		return "identity"
	}
	return "invalid"
}

// ParseComponent returns the component persisted as name, for store implementations reading the
// outbox back. It returns ErrUnknownComponent for any other name.
func ParseComponent(name string) (Component, error) {
	for _, c := range Components() {
		if c.String() == name {
			return c, nil
		}
	}
	return 0, errors.Join(ErrUnknownComponent, errors.New(name))
}

// OutboxItem is one pending lifecycle effect, written by Apply in the transaction of its mutation.
// The fields after Keep apply to one event only and are zero otherwise: Rotation to
// EventCredentialRotated, Change to EventFactorsChanged, Identifier and Old (the value before the
// change, zero when there was none) to EventIdentifierChanged.
type OutboxItem struct {
	ID            int64
	Component     Component
	Event         Event
	Subject       principal.Subject
	Keep          uuid.UUID
	Rotation      RotationReason
	Change        FactorChange
	Identifier    IdentifierKind
	Old           Identifier
	Attempts      int
	NextAttemptAt time.Time
	CreatedAt     time.Time
}

// Applied is the result of Apply: the subject (new for CreateVerified), its security epoch after
// the mutation and the outbox rows written with it, which the caller dispatches after commit.
type Applied struct {
	Subject  principal.Subject
	NewEpoch uint64
	Outbox   []OutboxItem
}

// EpochChange is one entry of the epoch feed: the subject's epoch after a security mutation.
type EpochChange struct {
	Subject  principal.Subject
	NewEpoch uint64
	Reason   Event
}
