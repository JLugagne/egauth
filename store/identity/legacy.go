package identity

import (
	"errors"

	"github.com/JLugagne/egauth/principal"
)

// IdentifierState tells whether v0.17 has checked the stored identifiers of an account against its
// normalisation. Its numeric value is persisted, so a value is never renumbered or reused.
type IdentifierState uint8

const (
	// IdentifiersUnchecked is every account a v0.16 deployment wrote: its email, phone or recovery
	// email may be a form v0.17 neither produces nor reads.
	IdentifiersUnchecked IdentifierState = 0
	// IdentifiersCanonical is every account CreateVerified creates, and every v0.16 account whose
	// identifiers the upgrade found or made canonical.
	IdentifiersCanonical IdentifierState = 1
	// IdentifiersHeld is a v0.16 account the upgrade checked and reported but could not make
	// canonical: an identifier v0.17 cannot represent, or one whose canonical form another live
	// account of the tenant owns. The held values stay verbatim.
	IdentifiersHeld IdentifierState = 2
)

// V016Identifiers is an account whose identifiers are not IdentifiersCanonical, with the stored
// values verbatim; an empty string is an absent phone or recovery email.
type V016Identifiers struct {
	Subject       principal.Subject
	Email         string
	Phone         string
	RecoveryEmail string
	Tombstoned    bool
	State         IdentifierState
}

// IdentifierUpgrade rewrites the identifiers of Old.Subject, provided they still equal Old and are
// not IdentifiersCanonical. A nil field keeps the stored value; a non-nil one replaces it and must
// hold an identifier of its kind. State is IdentifiersCanonical or IdentifiersHeld.
type IdentifierUpgrade struct {
	Old           V016Identifiers
	Email         *Identifier
	Phone         *Identifier
	RecoveryEmail *Identifier
	State         IdentifierState
}

// ValidateUpgrade returns ErrInvalidMutation for an IdentifierUpgrade that no store may apply.
func ValidateUpgrade(u IdentifierUpgrade) error {
	bad := func(id *Identifier, k IdentifierKind) bool { return id != nil && id.Kind() != k }
	switch {
	case u.Old.Subject.IsZero():
		return errors.Join(ErrInvalidMutation, errNoSubject)
	case u.State != IdentifiersCanonical && u.State != IdentifiersHeld:
		return errors.Join(ErrInvalidMutation, errors.New("the upgraded state must be canonical or held"))
	case bad(u.Email, IdentifierEmail), bad(u.Phone, IdentifierPhone), bad(u.RecoveryEmail, IdentifierRecoveryEmail):
		return errors.Join(ErrInvalidMutation, errors.New("an upgraded identifier has the wrong kind"))
	}
	return nil
}

// ErrIdentifiersHeld is returned by Store.Apply for a mutation that would rely on, replace or add
// to the credentials or identifiers of an account that is IdentifiersHeld or whose stored email,
// phone or recovery email is not canonical: its security notices may reach no one. Only protective
// mutations apply until an operator repairs it: SetDisabledState, SetMustChange, UnlinkFederated,
// Tombstone, a BumpEpoch that removes a TOTP or a passkey, a SetPassword of RotationSecurityRevert
// or RotationTemporaryPassword, and a SetPhone or SetRecoveryEmail that clears the value.
var ErrIdentifiersHeld = errors.New("identity: the account holds a v0.16 identifier awaiting repair")
