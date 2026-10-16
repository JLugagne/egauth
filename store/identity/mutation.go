package identity

import (
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

// MaxPHCLen bounds an encoded password hash, in bytes.
const MaxPHCLen = 1024

// MaxProviderLen bounds a federated provider name and provider subject, in bytes.
const MaxProviderLen = 255

// Mutation is one intent applied by Store.Apply. The set is closed: only the twelve value types of
// this package are accepted, and Validate refuses anything else, including a foreign struct that
// embeds one of them or a pointer to one. Each touches only its own columns (I-24). Effects tells
// which mutations bump the security epoch and which lifecycle event they queue.
type Mutation interface {
	validate() error
	effects() Effects
}

// Effects is what Apply does besides the mutation itself, in the same transaction: bump the
// subject's security epoch and append an epoch-log row, and queue Event in the outbox, one row per
// Component. A zero Event queues nothing.
type Effects struct {
	BumpsEpoch bool
	Event      Event
}

// Validate returns ErrInvalidMutation, joined with the reason, unless m is complete and consistent;
// Apply calls it first and changes nothing on error.
func Validate(m Mutation) error {
	if !declared(m) {
		return errors.Join(ErrInvalidMutation, errors.New("not a mutation of this package"))
	}
	if err := m.validate(); err != nil {
		return errors.Join(ErrInvalidMutation, err)
	}
	return nil
}

// EffectsOf returns the effects every store applies for m; the zero Effects for a nil m or any
// value Validate refuses as foreign.
func EffectsOf(m Mutation) Effects {
	if !declared(m) {
		return Effects{}
	}
	return m.effects()
}

func declared(m Mutation) bool {
	switch m.(type) {
	case SetPassword, MarkEmailVerified, ChangeEmail, SetPhone, SetRecoveryEmail, SetDisabledState,
		SetMustChange, Tombstone, BumpEpoch, CreateVerified, LinkFederated, UnlinkFederated:
		return true
	}
	return false
}

var errNoSubject = errors.New("subject is required")

// SetPassword replaces the subject's password hash, clears its lockout and sets must_change to
// Reason.ForcesChange(). Keep is the lineage that survives the rotation and is allowed only for
// RotationPasswordChanged.
type SetPassword struct {
	Subject principal.Subject
	PHC     PasswordHash
	Reason  RotationReason
	Keep    uuid.UUID
}

func (m SetPassword) validate() error {
	switch {
	case m.Subject.IsZero():
		return errNoSubject
	case m.PHC.IsZero() || len(m.PHC.PHC()) > MaxPHCLen:
		return errors.New("password hash is required and bounded")
	case !m.Reason.Valid():
		return errors.New("invalid rotation reason")
	case m.Keep != uuid.Nil && m.Reason != RotationPasswordChanged:
		return errors.New("only a password change keeps a session")
	}
	return nil
}

func (SetPassword) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventCredentialRotated}
}

// String renders m with the hash redacted.
func (m SetPassword) String() string {
	return "identity.SetPassword{PHC: REDACTED, Reason: " + m.Reason.String() + "}"
}

// GoString renders m for %#v with the hash redacted.
func (m SetPassword) GoString() string { return m.String() }

// LogValue renders m for slog with the hash redacted.
func (m SetPassword) LogValue() slog.Value {
	return slog.GroupValue(slog.String("phc", "REDACTED"), slog.String("reason", m.Reason.String()))
}

// MarkEmailVerified records the first proof of ownership of an unverified email (/email/verify, or
// a registration confirm reaching an existing unverified account). In the same transaction it wipes
// every credential set before verification (C-39): the password credential with its lockout,
// must_change and every federated link; PHC, when set, becomes the only password afterwards
// (registration confirm). The bump revokes every session; the queued EventIdentifierChanged carries
// no previous address, so it deletes the pending links, codes, resets and verifications of the
// subject and sends no notice.
// Passkeys and TOTP live in other stores: the caller removes them first, each behind BumpEpoch, and
// applies MarkEmailVerified last, so a crash in between leaves the account unverified and retryable,
// never verified with a pre-verification credential.
type MarkEmailVerified struct {
	Subject principal.Subject
	PHC     PasswordHash
}

func (m MarkEmailVerified) validate() error {
	switch {
	case m.Subject.IsZero():
		return errNoSubject
	case len(m.PHC.PHC()) > MaxPHCLen:
		return errors.New("password hash is too long")
	}
	return nil
}

func (MarkEmailVerified) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventIdentifierChanged}
}

// String renders m with the hash redacted.
func (m MarkEmailVerified) String() string {
	return "identity.MarkEmailVerified{PHC: REDACTED}"
}

// GoString renders m for %#v with the hash redacted.
func (m MarkEmailVerified) GoString() string { return m.String() }

// LogValue renders m for slog with the hash redacted.
func (m MarkEmailVerified) LogValue() slog.Value {
	return slog.GroupValue(slog.String("phc", "REDACTED"), slog.Bool("sets_password", !m.PHC.IsZero()))
}

// ChangeEmail sets a new, verified email; the outbox carries the previous one so that the notice
// reaches the address that lost access.
type ChangeEmail struct {
	Subject principal.Subject
	Email   Identifier
}

func (m ChangeEmail) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	if m.Email.Kind() != IdentifierEmail {
		return errors.New("email identifier is required")
	}
	return nil
}

func (ChangeEmail) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventIdentifierChanged}
}

// SetPhone sets a verified phone, or removes it when Phone is zero.
type SetPhone struct {
	Subject principal.Subject
	Phone   Identifier
}

func (m SetPhone) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	if !m.Phone.IsZero() && m.Phone.Kind() != IdentifierPhone {
		return errors.New("phone identifier expected")
	}
	return nil
}

func (SetPhone) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventIdentifierChanged}
}

// SetRecoveryEmail sets a verified recovery email, or removes it when RecoveryEmail is zero.
type SetRecoveryEmail struct {
	Subject       principal.Subject
	RecoveryEmail Identifier
}

func (m SetRecoveryEmail) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	if !m.RecoveryEmail.IsZero() && m.RecoveryEmail.Kind() != IdentifierRecoveryEmail {
		return errors.New("recovery email identifier expected")
	}
	return nil
}

func (SetRecoveryEmail) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventIdentifierChanged}
}

// SetDisabledState disables the account (Disable true: the epoch is bumped, so every session ends)
// or enables it again (no bump: nothing revoked comes back). DESIGN §4.7 calls it SetDisabled; the
// G07 opt-out-name rule reserves a trailing "Disabled" for insecure switches.
type SetDisabledState struct {
	Subject principal.Subject
	Disable bool
}

func (m SetDisabledState) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	return nil
}

func (m SetDisabledState) effects() Effects {
	if m.Disable {
		return Effects{BumpsEpoch: true, Event: EventDisable}
	}
	return Effects{Event: EventEnable}
}

// SetMustChange sets or clears must_change; sessions pick it up at their next renewal.
type SetMustChange struct {
	Subject    principal.Subject
	MustChange bool
}

func (m SetMustChange) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	return nil
}

func (SetMustChange) effects() Effects { return Effects{} }

// Tombstone deletes the account: it sets deleted_at and frees its identifiers. The row itself is
// removed by EraseUser once every outbox component of the subject is done (C-03).
type Tombstone struct {
	Subject principal.Subject
}

func (m Tombstone) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	return nil
}

func (Tombstone) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventDelete}
}

// BumpEpoch records a factor change made in another store (TOTP, recovery codes, passkeys). It is
// applied before that change, so a crash in between only ends sessions. Keep is the lineage that
// survives. Federated changes go through LinkFederated and UnlinkFederated instead.
type BumpEpoch struct {
	Subject principal.Subject
	Keep    uuid.UUID
	Change  FactorChange
}

func (m BumpEpoch) validate() error {
	switch {
	case m.Subject.IsZero():
		return errNoSubject
	case !m.Change.Valid():
		return errors.New("invalid factor change")
	case m.Change == FactorFederatedLinked || m.Change == FactorFederatedUnlinked:
		return errors.New("federated changes use LinkFederated or UnlinkFederated")
	}
	return nil
}

func (BumpEpoch) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventFactorsChanged}
}

// CreateVerified creates an account whose email is already verified (registration confirmed, an
// administrator, or a federated sign-up with Federated set). PHC is zero for an account without a
// password; MustChange requires one. The store picks the user id and returns it in Applied.Subject.
type CreateVerified struct {
	Tenant     principal.TenantID
	Email      Identifier
	PHC        PasswordHash
	MustChange bool
	Federated  FederatedIdentity
}

func (m CreateVerified) validate() error {
	switch {
	case m.Email.Kind() != IdentifierEmail:
		return errors.New("email identifier is required")
	case len(m.PHC.PHC()) > MaxPHCLen:
		return errors.New("password hash is too long")
	case m.MustChange && m.PHC.IsZero():
		return errors.New("must change requires a password")
	case m.Federated != (FederatedIdentity{}):
		return checkFederated(m.Federated)
	}
	return nil
}

func (CreateVerified) effects() Effects { return Effects{} }

// String renders m with the hash redacted.
func (m CreateVerified) String() string {
	return "identity.CreateVerified{PHC: REDACTED}"
}

// GoString renders m for %#v with the hash redacted.
func (m CreateVerified) GoString() string { return m.String() }

// LogValue renders m for slog with the hash redacted.
func (m CreateVerified) LogValue() slog.Value {
	return slog.GroupValue(slog.String("phc", "REDACTED"), slog.String("tenant", m.Tenant.String()))
}

// LinkFederated links a provider account to an existing subject. It is an authenticated action and
// never follows from a matching email (D6). Keep is the lineage that survives. When the subject
// already holds the provider account under another Authority, the link is re-bound to Identity,
// with the same epoch bump and FactorsChanged notice; under the same Authority it is
// store.ErrConflict.
type LinkFederated struct {
	Subject  principal.Subject
	Identity FederatedIdentity
	Keep     uuid.UUID
}

func (m LinkFederated) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	return checkFederated(m.Identity)
}

func (LinkFederated) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventFactorsChanged}
}

// UnlinkFederated removes the subject's link to a provider account. Keep is the lineage that
// survives.
type UnlinkFederated struct {
	Subject         principal.Subject
	Provider        string
	ProviderSubject string
	Keep            uuid.UUID
}

func (m UnlinkFederated) validate() error {
	if m.Subject.IsZero() {
		return errNoSubject
	}
	return checkFederatedKey(m.Provider, m.ProviderSubject)
}

func (UnlinkFederated) effects() Effects {
	return Effects{BumpsEpoch: true, Event: EventFactorsChanged}
}

func checkFederatedKey(provider, subject string) error {
	switch {
	case provider == "" || len(provider) > MaxProviderLen:
		return errors.New("provider is required and bounded")
	case subject == "" || len(subject) > MaxProviderLen:
		return errors.New("provider subject is required and bounded")
	}
	return nil
}

func checkFederated(f FederatedIdentity) error {
	if err := checkFederatedKey(f.Provider, f.ProviderSubject); err != nil {
		return err
	}
	switch {
	case f.Authority == "" || len(f.Authority) > MaxProviderLen:
		return errors.New("authority is required and bounded")
	case !f.ProviderEmail.IsZero() && f.ProviderEmail.Kind() != IdentifierEmail:
		return errors.New("provider email must be an email identifier")
	case f.ProviderEmailVerified && f.ProviderEmail.IsZero():
		return errors.New("a verified provider email needs an email")
	}
	return nil
}

// OutboxFor returns the outbox rows every store writes when it applies m to subject s: one per
// Component, in Components order, or nil when m queues no event. old is the identifier m replaced,
// zero when there was none; it is ignored for MarkEmailVerified, which replaces no address. The
// store sets ID, Attempts, NextAttemptAt and CreatedAt.
func OutboxFor(m Mutation, s principal.Subject, old Identifier) []OutboxItem {
	ev := EffectsOf(m).Event
	if ev == 0 {
		return nil
	}
	tmpl := OutboxItem{Event: ev, Subject: s}
	switch x := m.(type) {
	case SetPassword:
		tmpl.Keep, tmpl.Rotation = x.Keep, x.Reason
	case BumpEpoch:
		tmpl.Keep, tmpl.Change = x.Keep, x.Change
	case LinkFederated:
		tmpl.Keep, tmpl.Change = x.Keep, FactorFederatedLinked
	case UnlinkFederated:
		tmpl.Keep, tmpl.Change = x.Keep, FactorFederatedUnlinked
	case ChangeEmail:
		tmpl.Identifier, tmpl.Old = IdentifierEmail, old
	case SetPhone:
		tmpl.Identifier, tmpl.Old = IdentifierPhone, old
	case SetRecoveryEmail:
		tmpl.Identifier, tmpl.Old = IdentifierRecoveryEmail, old
	case MarkEmailVerified:
		tmpl.Identifier = IdentifierEmail
	}
	out := make([]OutboxItem, 0, int(componentEnd)-1)
	for _, c := range Components() {
		item := tmpl
		item.Component = c
		out = append(out, item)
	}
	return out
}
