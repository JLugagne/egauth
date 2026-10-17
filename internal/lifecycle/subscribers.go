package lifecycle

import (
	"context"
	"errors"
	"reflect"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/tokens"
)

// ErrInvalidWiring is returned by the adapter constructors for a missing dependency and by
// NewDispatcher, joined with one error per problem, for an incomplete or mismatched wiring.
var ErrInvalidWiring = errors.New("lifecycle: invalid subscriber wiring")

type adapter interface {
	forRow(item identity.OutboxItem) Subscriber
	component() identity.Component
	cells() Cells
	usable() bool
	dependency() any
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

func missing(name string) error {
	return errors.Join(ErrInvalidWiring, errors.New(name+" is required"))
}

type none struct{}

func (none) OnCredentialRotated(context.Context, CredentialRotated) error { return nil }
func (none) OnFactorsChanged(context.Context, FactorsChanged) error       { return nil }
func (none) OnIdentifierChanged(context.Context, IdentifierChanged) error { return nil }
func (none) OnDisabled(context.Context, AccountEvent) error               { return nil }
func (none) OnEnabled(context.Context, AccountEvent) error                { return nil }
func (none) OnDeleted(context.Context, AccountEvent) error                { return nil }
func (none) OnTenantErased(context.Context, TenantErased) error           { return nil }
func (none) OnSessionEnded(context.Context, SessionEnded) error           { return nil }

// Sessions is the session-backend row of the matrix: it forwards every event to the Backend, whose
// own suite proves each revocation (internal/session).
type Sessions struct {
	backend Subscriber
}

// NewSessions wraps the session Backend. It returns ErrInvalidWiring for a nil backend.
func NewSessions(backend Subscriber) (*Sessions, error) {
	if !present(backend) {
		return nil, missing("session backend")
	}
	return &Sessions{backend: backend}, nil
}

func (s *Sessions) forRow(identity.OutboxItem) Subscriber { return s }
func (s *Sessions) component() identity.Component         { return identity.ComponentSessions }
func (s *Sessions) cells() Cells                          { return Golden()[identity.ComponentSessions] }
func (s *Sessions) usable() bool                          { return s != nil && present(s.backend) }
func (s *Sessions) dependency() any                       { return s.backend }

// Backend returns the wrapped session backend, so the composition root can prove the dispatcher
// revokes the sessions of the backend it serves (see Dispatcher.Wired).
func (s *Sessions) Backend() Subscriber { return s.backend }

func (s *Sessions) OnCredentialRotated(ctx context.Context, e CredentialRotated) error {
	return s.backend.OnCredentialRotated(ctx, e)
}

func (s *Sessions) OnFactorsChanged(ctx context.Context, e FactorsChanged) error {
	return s.backend.OnFactorsChanged(ctx, e)
}

func (s *Sessions) OnIdentifierChanged(ctx context.Context, e IdentifierChanged) error {
	return s.backend.OnIdentifierChanged(ctx, e)
}

func (s *Sessions) OnDisabled(ctx context.Context, e AccountEvent) error {
	return s.backend.OnDisabled(ctx, e)
}

func (s *Sessions) OnEnabled(ctx context.Context, e AccountEvent) error {
	return s.backend.OnEnabled(ctx, e)
}

func (s *Sessions) OnDeleted(ctx context.Context, e AccountEvent) error {
	return s.backend.OnDeleted(ctx, e)
}

func (s *Sessions) OnTenantErased(ctx context.Context, e TenantErased) error {
	return s.backend.OnTenantErased(ctx, e)
}

func (s *Sessions) OnSessionEnded(ctx context.Context, e SessionEnded) error {
	return s.backend.OnSessionEnded(ctx, e)
}

// APIKeys is the API-key row. A password, factor or identifier change leaves keys alone (T-05):
// a disabled owner's keys are refused by the owner-state check at verification, and enabling the
// owner makes them usable again. Deletion erases every key of the subject.
type APIKeys struct {
	none
	tokens tokens.Store
	absent bool
}

// NewAPIKeys returns the API-key row over the tokens store. It returns ErrInvalidWiring for a nil
// store.
func NewAPIKeys(s tokens.Store) (*APIKeys, error) {
	if !present(s) {
		return nil, missing("tokens store")
	}
	return &APIKeys{tokens: s}, nil
}

// AbsentAPIKeys is the API-key row of a deployment without a tokens store, which holds no key.
func AbsentAPIKeys() *APIKeys { return &APIKeys{absent: true} }

func (a *APIKeys) forRow(identity.OutboxItem) Subscriber { return a }
func (a *APIKeys) dependency() any {
	if a.absent {
		return nil
	}
	return a.tokens
}

func (a *APIKeys) component() identity.Component { return identity.ComponentAPIKeys }
func (a *APIKeys) usable() bool                  { return a != nil && (a.absent || present(a.tokens)) }

func (a *APIKeys) cells() Cells {
	if a.absent {
		return uniform(CellAbsent)
	}
	return Golden()[identity.ComponentAPIKeys]
}

// OnDeleted erases every API key and refresh family of the subject.
func (a *APIKeys) OnDeleted(ctx context.Context, e AccountEvent) error {
	if a.absent {
		return nil
	}
	return a.tokens.DeleteForSubject(ctx, e.Subject)
}

// OnTenantErased erases the tenant's API keys and refresh families.
func (a *APIKeys) OnTenantErased(ctx context.Context, e TenantErased) error {
	if a.absent {
		return nil
	}
	return a.tokens.EraseTenant(ctx, e.Tenant)
}

// AccountReader reads the account whose identifier-scoped ceremonies are deleted.
type AccountReader interface {
	GetUser(ctx context.Context, s principal.Subject) (identity.User, error)
}

// Scoper computes the scopes ceremony records are stored under (identitysvc.Accounts).
type Scoper interface {
	// Scope returns the identifier scope of id.
	Scope(id identity.Identifier) (ceremony.Scope, error)
	// RevertScopes returns every scope holding SecurityRevert bookkeeping of the subject beyond its
	// current identifiers (anchors, span, lock and tenure records), never the links sent to previous
	// addresses. Deleting them in the order returned, stopping at the first failure, keeps the rest
	// retryable.
	RevertScopes(ctx context.Context, s principal.Subject, current []identity.Identifier) ([]ceremony.Scope, error)
}

var (
	rotatedSubject    = []ceremony.Kind{ceremony.PasswordReset, ceremony.PasswordResetCode, ceremony.MFAFlow}
	signInIdentifier  = []ceremony.Kind{ceremony.MagicLink, ceremony.EmailCode, ceremony.SMSCode}
	factorSubject     = []ceremony.Kind{ceremony.MFAFlow, ceremony.MFAPasskey}
	identifierSubject = []ceremony.Kind{
		ceremony.PasswordReset, ceremony.PasswordResetCode, ceremony.EmailVerification,
		ceremony.PhoneVerification, ceremony.EmailChange, ceremony.RecoveryEmail,
	}
)

func storedKinds(class ceremony.ScopeClass, keepRevert bool) []ceremony.Kind {
	var out []ceremony.Kind
	for _, k := range ceremony.All() {
		if k.Scope() == class && (!keepRevert || k != ceremony.SecurityRevert) {
			out = append(out, k)
		}
	}
	return out
}

// CeremoniesWiring is what the ceremony row acts on, as Dispatcher.Wired reports it: a stand-in
// reader or a Scoper keyed differently silently deletes no identifier-scoped ceremony.
type CeremoniesWiring struct {
	Store    ceremony.Store
	Accounts AccountReader
	Scoper   Scoper
}

// Ceremonies is the ceremony row. It deletes the subject-scoped records of the subject and the
// identifier-scoped records of its email, phone and recovery email (and of the replaced identifier
// for IdentifierChanged). A disable keeps the SecurityRevert links addressed to the current
// identifiers, the owner's way back (a deliberate narrowing of DESIGN 7.2 "delete all"); a deletion
// also erases the revert bookkeeping (Scoper.RevertScopes). Revert links sent to previous addresses
// are left to their 7-day TTL: that scope is per address, not per subject, and may hold another
// account's links.
// A row retried after a later ceremony was issued deletes that one too; this fails safe, the user
// asks again.
type Ceremonies struct {
	store    ceremony.Store
	accounts AccountReader
	scopes   Scoper
}

// NewCeremonies returns the ceremony row. It returns ErrInvalidWiring for a nil argument.
func NewCeremonies(s ceremony.Store, accounts AccountReader, scopes Scoper) (*Ceremonies, error) {
	var errs []error
	if !present(s) {
		errs = append(errs, missing("ceremony store"))
	}
	if !present(accounts) {
		errs = append(errs, missing("account reader"))
	}
	if !present(scopes) {
		errs = append(errs, missing("scoper"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Ceremonies{store: s, accounts: accounts, scopes: scopes}, nil
}

func (c *Ceremonies) forRow(identity.OutboxItem) Subscriber { return c }
func (c *Ceremonies) dependency() any {
	return CeremoniesWiring{Store: c.store, Accounts: c.accounts, Scoper: c.scopes}
}
func (c *Ceremonies) component() identity.Component { return identity.ComponentCeremonies }
func (c *Ceremonies) cells() Cells                  { return Golden()[identity.ComponentCeremonies] }

func (c *Ceremonies) usable() bool {
	return c != nil && present(c.store) && present(c.accounts) && present(c.scopes)
}

func (c *Ceremonies) deleteSubject(ctx context.Context, s principal.Subject, kinds []ceremony.Kind) error {
	_, err := c.store.DeleteForScope(ctx, s.Tenant, ceremony.SubjectScope(s).Hash(), kinds...)
	return err
}

func (c *Ceremonies) currentIdentifiers(ctx context.Context, s principal.Subject) ([]identity.Identifier, error) {
	u, err := c.accounts.GetUser(ctx, s)
	switch {
	case err == nil:
		return []identity.Identifier{u.Email, u.Phone, u.RecoveryEmail}, nil
	case errors.Is(err, store.ErrNotFound):
		return nil, nil
	}
	return nil, err
}

func (c *Ceremonies) deleteIdentifiers(ctx context.Context, s principal.Subject, kinds []ceremony.Kind, extra ...identity.Identifier) error {
	current, err := c.currentIdentifiers(ctx, s)
	if err != nil {
		return err
	}
	ids := append(extra, current...)
	var errs []error
	for _, id := range ids {
		if id.IsZero() {
			continue
		}
		scope, err := c.scopes.Scope(id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := c.store.DeleteForScope(ctx, s.Tenant, scope.Hash(), kinds...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Ceremonies) deleteReverts(ctx context.Context, s principal.Subject) error {
	current, err := c.currentIdentifiers(ctx, s)
	if err != nil {
		return err
	}
	scopes, err := c.scopes.RevertScopes(ctx, s, current)
	if err != nil {
		return err
	}
	kinds := storedKinds(ceremony.Identifier, false)
	for _, scope := range scopes {
		if _, err := c.store.DeleteForScope(ctx, s.Tenant, scope.Hash(), kinds...); err != nil {
			return err
		}
	}
	return nil
}

func (c *Ceremonies) deleteAll(ctx context.Context, s principal.Subject, keepRevert bool) error {
	errs := []error{
		c.deleteSubject(ctx, s, storedKinds(ceremony.Subject, keepRevert)),
		c.deleteIdentifiers(ctx, s, storedKinds(ceremony.Identifier, keepRevert)),
	}
	if !keepRevert {
		errs = append(errs, c.deleteReverts(ctx, s))
	}
	return errors.Join(errs...)
}

// OnCredentialRotated deletes the subject's reset links and codes, MFA flows, and the sign-in links
// and codes of its identifiers; SecurityRevert links survive, so a hijacker's password change
// cannot disarm the owner's revert (C-45).
func (c *Ceremonies) OnCredentialRotated(ctx context.Context, e CredentialRotated) error {
	return errors.Join(
		c.deleteSubject(ctx, e.Subject, rotatedSubject),
		c.deleteIdentifiers(ctx, e.Subject, signInIdentifier),
	)
}

// OnFactorsChanged deletes the subject's MFA flows and MFA passkey challenges.
func (c *Ceremonies) OnFactorsChanged(ctx context.Context, e FactorsChanged) error {
	return c.deleteSubject(ctx, e.Subject, factorSubject)
}

// OnIdentifierChanged deletes the sign-in links and codes of the replaced and current identifiers,
// and the subject's reset and verification ceremonies.
func (c *Ceremonies) OnIdentifierChanged(ctx context.Context, e IdentifierChanged) error {
	var old []identity.Identifier
	if e.Old != "" {
		if id, err := identity.NewIdentifier(identity.IdentifierKind(e.Kind), e.Old); err == nil {
			old = append(old, id)
		}
	}
	return errors.Join(
		c.deleteSubject(ctx, e.Subject, identifierSubject),
		c.deleteIdentifiers(ctx, e.Subject, signInIdentifier, old...),
	)
}

// OnDisabled deletes every stored ceremony of the subject except the SecurityRevert records.
func (c *Ceremonies) OnDisabled(ctx context.Context, e AccountEvent) error {
	return c.deleteAll(ctx, e.Subject, true)
}

func (c *Ceremonies) OnEnabled(context.Context, AccountEvent) error { return nil }

// OnDeleted deletes every stored ceremony of the subject.
func (c *Ceremonies) OnDeleted(ctx context.Context, e AccountEvent) error {
	return c.deleteAll(ctx, e.Subject, false)
}

func (c *Ceremonies) OnTenantErased(ctx context.Context, e TenantErased) error {
	return c.store.EraseTenant(ctx, e.Tenant)
}

func (c *Ceremonies) OnSessionEnded(context.Context, SessionEnded) error { return nil }

type subjectEraser interface {
	store.Base
	DeleteForSubject(ctx context.Context, s principal.Subject) error
}

type eraser struct {
	none
	store  subjectEraser
	absent bool
}

func (e eraser) usable() bool { return e.absent || present(e.store) }

func (e eraser) dependency() any {
	if e.absent {
		return nil
	}
	return e.store
}

func (e eraser) row(c identity.Component) Cells {
	if e.absent {
		return uniform(CellAbsent)
	}
	return Golden()[c]
}

func (e eraser) OnDeleted(ctx context.Context, ev AccountEvent) error {
	if e.absent {
		return nil
	}
	return e.store.DeleteForSubject(ctx, ev.Subject)
}

func (e eraser) OnTenantErased(ctx context.Context, ev TenantErased) error {
	if e.absent {
		return nil
	}
	return e.store.EraseTenant(ctx, ev.Tenant)
}

// MFA is the TOTP and recovery-code row. Only deletion erases the enrollment: a credential
// rotation never does (I-09), so a mailbox takeover that resets the password still meets the
// second factor.
type MFA struct{ eraser }

// NewMFA returns the MFA row. It returns ErrInvalidWiring for a nil store.
func NewMFA(s mfa.Store) (*MFA, error) {
	if !present(s) {
		return nil, missing("mfa store")
	}
	return &MFA{eraser{store: s}}, nil
}

func (m *MFA) forRow(identity.OutboxItem) Subscriber { return m }
func (m *MFA) component() identity.Component         { return identity.ComponentMFA }
func (m *MFA) cells() Cells                          { return m.row(identity.ComponentMFA) }
func (m *MFA) usable() bool                          { return m != nil && m.eraser.usable() }

// Passkeys is the passkey row. Only deletion erases credentials; a credential rotation never does
// (I-09).
type Passkeys struct{ eraser }

// NewPasskeys returns the passkey row. It returns ErrInvalidWiring for a nil store.
func NewPasskeys(s passkey.Store) (*Passkeys, error) {
	if !present(s) {
		return nil, missing("passkey store")
	}
	return &Passkeys{eraser{store: s}}, nil
}

func (p *Passkeys) forRow(identity.OutboxItem) Subscriber { return p }
func (p *Passkeys) component() identity.Component         { return identity.ComponentPasskeys }
func (p *Passkeys) cells() Cells                          { return p.row(identity.ComponentPasskeys) }
func (p *Passkeys) usable() bool                          { return p != nil && p.eraser.usable() }

// Federation is the row of the federation store's linked identities; the links held by the
// identity store go with the account (EraseUser).
type Federation struct{ eraser }

// NewFederation returns the federation row. It returns ErrInvalidWiring for a nil store.
func NewFederation(s federation.Store) (*Federation, error) {
	if !present(s) {
		return nil, missing("federation store")
	}
	return &Federation{eraser{store: s}}, nil
}

// AbsentFederation is the federation row of a deployment without a federation store.
func AbsentFederation() *Federation { return &Federation{eraser{absent: true}} }

func (f *Federation) forRow(identity.OutboxItem) Subscriber { return f }
func (f *Federation) component() identity.Component         { return identity.ComponentFederation }
func (f *Federation) cells() Cells                          { return f.row(identity.ComponentFederation) }
func (f *Federation) usable() bool                          { return f != nil && f.eraser.usable() }

// NoticeSender sends the security notice of one outbox row (identitysvc.Accounts.SecurityNotice).
// It decides the recipient from the row and must be idempotent on the row: a retry re-sends the
// same DeliveryID.
type NoticeSender interface {
	SecurityNotice(ctx context.Context, item identity.OutboxItem) error
}

// Notices is the security-notice row. A notice needs the outbox row itself (its id and creation
// time date the revert link), so the dispatcher asks For a per-row Subscriber.
type Notices struct {
	send NoticeSender
}

// NewNotices returns the notice row. It returns ErrInvalidWiring for a nil send. Wired exposes send,
// so G18 can check it is the Accounts the composed Auth owns.
func NewNotices(send NoticeSender) (*Notices, error) {
	if !present(send) {
		return nil, missing("notice sender")
	}
	return &Notices{send: send}, nil
}

func (n *Notices) forRow(item identity.OutboxItem) Subscriber { return n.For(item) }
func (n *Notices) dependency() any                            { return n.send }
func (n *Notices) component() identity.Component              { return identity.ComponentNotices }
func (n *Notices) cells() Cells                               { return Golden()[identity.ComponentNotices] }
func (n *Notices) usable() bool                               { return n != nil && present(n.send) }

// For returns the Subscriber that handles item: credential, factor and identifier changes send the
// row's notice; every other event sends nothing.
func (n *Notices) For(item identity.OutboxItem) Subscriber {
	return noticeRow{send: n.send, item: item}
}

type noticeRow struct {
	none
	send NoticeSender
	item identity.OutboxItem
}

func (r noticeRow) OnCredentialRotated(ctx context.Context, _ CredentialRotated) error {
	return r.send.SecurityNotice(ctx, r.item)
}

func (r noticeRow) OnFactorsChanged(ctx context.Context, _ FactorsChanged) error {
	return r.send.SecurityNotice(ctx, r.item)
}

func (r noticeRow) OnIdentifierChanged(ctx context.Context, _ IdentifierChanged) error {
	return r.send.SecurityNotice(ctx, r.item)
}

// Keys is the tenant signing-key row. Erasing a tenant tombstones it before erasing its keys, so
// lazy provisioning can never mint keys for it again (T-13).
type Keys struct {
	none
	keys   keys.Store
	absent bool
}

// NewKeys returns the key row. It returns ErrInvalidWiring for a nil store.
func NewKeys(s keys.Store) (*Keys, error) {
	if !present(s) {
		return nil, missing("keys store")
	}
	return &Keys{keys: s}, nil
}

// AbsentKeys is the key row of a deployment without a tenant-keys store.
func AbsentKeys() *Keys { return &Keys{absent: true} }

func (k *Keys) forRow(identity.OutboxItem) Subscriber { return k }
func (k *Keys) dependency() any {
	if k.absent {
		return nil
	}
	return k.keys
}

func (k *Keys) component() identity.Component { return identity.ComponentKeys }
func (k *Keys) usable() bool                  { return k != nil && (k.absent || present(k.keys)) }

func (k *Keys) cells() Cells {
	if k.absent {
		return uniform(CellAbsent)
	}
	return Golden()[identity.ComponentKeys]
}

// OnTenantErased tombstones the tenant, then erases its keys.
func (k *Keys) OnTenantErased(ctx context.Context, e TenantErased) error {
	if k.absent {
		return nil
	}
	if err := k.keys.Tombstone(ctx, e.Tenant); err != nil {
		return err
	}
	return k.keys.EraseTenant(ctx, e.Tenant)
}

// AccountDeletedHook is the application's Hooks.AccountDeleted.
type AccountDeletedHook func(ctx context.Context, deliveryID uuid.UUID, s principal.Subject) error

// TenantErasedHook is the application's Hooks.TenantErased.
type TenantErasedHook func(ctx context.Context, deliveryID uuid.UUID, t principal.TenantID) error

var hookNamespace = uuid.MustParse("0f6c3b8e-58a2-4c55-9d3e-2b7e61a4c9d1")

// Hooks is the application-hook row. A hook is retried until it returns nil, with a DeliveryID
// derived from the subject or the tenant, so every retry, and a replay on another instance, carries
// the same id.
type Hooks struct {
	none
	accountDeleted AccountDeletedHook
	tenantErased   TenantErasedHook
}

// NewHooks returns the hook row; a nil hook is not called.
func NewHooks(accountDeleted AccountDeletedHook, tenantErased TenantErasedHook) *Hooks {
	return &Hooks{accountDeleted: accountDeleted, tenantErased: tenantErased}
}

func (h *Hooks) forRow(identity.OutboxItem) Subscriber { return h }
func (h *Hooks) component() identity.Component         { return identity.ComponentHooks }
func (h *Hooks) dependency() any                       { return nil }

func (h *Hooks) cells() Cells {
	c := Golden()[identity.ComponentHooks]
	if h.accountDeleted == nil {
		c.Delete = CellNone
	}
	if h.tenantErased == nil {
		c.TenantErased = CellNone
	}
	return c
}
func (h *Hooks) usable() bool { return h != nil }

// OnDeleted calls Hooks.AccountDeleted.
func (h *Hooks) OnDeleted(ctx context.Context, e AccountEvent) error {
	if h.accountDeleted == nil {
		return nil
	}
	id := uuid.NewSHA1(hookNamespace, []byte("account_deleted/"+e.Subject.Tenant.String()+"/"+e.Subject.User.String()))
	return h.accountDeleted(ctx, id, e.Subject)
}

// OnTenantErased calls Hooks.TenantErased.
func (h *Hooks) OnTenantErased(ctx context.Context, e TenantErased) error {
	if h.tenantErased == nil {
		return nil
	}
	id := uuid.NewSHA1(hookNamespace, []byte("tenant_erased/"+e.Tenant.String()))
	return h.tenantErased(ctx, id, e.Tenant)
}

// IdentityEraser is the part of identity.Store the identity row calls.
type IdentityEraser interface {
	store.Base
	EraseUser(ctx context.Context, s principal.Subject) error
}

// Identity is the account row. It hard-deletes a tombstoned account only once every other outbox
// row of the subject is done: EraseUser refuses with store.ErrConflict before that, and the
// dispatcher defers the row without reporting a failure.
type Identity struct {
	none
	store IdentityEraser
}

// NewIdentity returns the account row. It returns ErrInvalidWiring for a nil store.
func NewIdentity(s IdentityEraser) (*Identity, error) {
	if !present(s) {
		return nil, missing("identity store")
	}
	return &Identity{store: s}, nil
}

func (i *Identity) forRow(identity.OutboxItem) Subscriber { return i }
func (i *Identity) dependency() any                       { return i.store }
func (i *Identity) component() identity.Component         { return identity.ComponentIdentity }
func (i *Identity) cells() Cells                          { return Golden()[identity.ComponentIdentity] }
func (i *Identity) usable() bool                          { return i != nil && present(i.store) }

// OnDeleted hard-deletes the tombstoned account; an account already erased is done.
func (i *Identity) OnDeleted(ctx context.Context, e AccountEvent) error {
	if err := i.store.EraseUser(ctx, e.Subject); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// OnTenantErased erases every account of the tenant; the dispatcher calls it last.
func (i *Identity) OnTenantErased(ctx context.Context, e TenantErased) error {
	return i.store.EraseTenant(ctx, e.Tenant)
}
