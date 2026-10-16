package federationsvc

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/store"
	storefed "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
)

// Registration says whether a provider identity linked to no account may create one. The zero value
// is invalid.
type Registration uint8

const (
	// RegistrationOpen creates an account for a new provider identity whose email is verified.
	RegistrationOpen Registration = iota + 1
	// RegistrationInviteOnly never creates an account: only already-linked identities sign in.
	RegistrationInviteOnly
)

func (r Registration) valid() bool { return r == RegistrationOpen || r == RegistrationInviteOnly }

// Users finds live accounts by email; identity.Store satisfies it.
type Users interface {
	FindUser(ctx context.Context, t core.TenantID, id identity.Identifier) (identity.User, error)
}

// Links finds the account linked to a provider identity; federation.Store satisfies it.
type Links interface {
	FindLinked(ctx context.Context, t core.TenantID, k storefed.LinkKey) (storefed.LinkedIdentity, error)
}

// Accounts is the account service: its state and its shared mutation path, which bumps the epoch
// and dispatches the outbox. identitysvc.Service satisfies it.
type Accounts interface {
	AccountState(ctx context.Context, sub core.Subject) (core.AccountState, error)
	Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error)
}

// ProviderIdentity is an account at an identity provider as the provider proved it. Provider is the
// federation provider name, or "external:" and the external factor name; Subject is the provider's
// stable id of the account. Authority is the store/federation StaticAuthority or RuntimeAuthority
// of the configuration that proved it: a link resolves only under the Authority it was made with.
// EmailVerified is the caller's final decision that Email may become an account email
// (federation.Provider.Verified for a federated provider).
type ProviderIdentity struct {
	Provider      string
	Subject       string
	Authority     string
	Email         string
	EmailVerified bool
}

func (p ProviderIdentity) key() storefed.LinkKey {
	return storefed.LinkKey{Provider: p.Provider, ProviderSubject: p.Subject}
}

func (p ProviderIdentity) valid() bool {
	for _, f := range []string{p.Provider, p.Subject, p.Authority} {
		if f == "" || len(f) > identity.MaxProviderLen {
			return false
		}
	}
	return true
}

func (p ProviderIdentity) email() (identity.Identifier, bool) {
	if p.Email == "" {
		return identity.Identifier{}, false
	}
	id, err := identitysvc.NormalizeAs(identity.IdentifierEmail, p.Email)
	return id, err == nil
}

// DirectoryConfig is what NewDirectory needs; every member is required.
type DirectoryConfig struct {
	Users        Users
	Links        Links
	Accounts     Accounts
	Registration Registration
	Audit        httpx.Audit
}

// Directory maps provider identities to accounts without ever attaching one to an existing account
// (D6): a sign-in either finds the account already linked to the identity or creates a new one.
// Linking is the separate, authenticated Link. It is shared by the federated and the external
// primary factors and is safe for concurrent use.
type Directory struct {
	users        Users
	links        Links
	accounts     Accounts
	registration Registration
	audit        httpx.Audit
}

// NewDirectory returns ErrInvalidConfig joined with every missing member.
func NewDirectory(cfg DirectoryConfig) (*Directory, error) {
	var errs []error
	for name, ok := range map[string]bool{
		"Users": present(cfg.Users), "Links": present(cfg.Links), "Accounts": present(cfg.Accounts),
		"Registration": cfg.Registration.valid(), "Audit": present(cfg.Audit),
	} {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Directory{users: cfg.Users, links: cfg.Links, accounts: cfg.Accounts, registration: cfg.Registration, audit: cfg.Audit}, nil
}

// SignIn returns the subject of tenant t that id signs in as. An identity linked under id.Authority
// signs in to its account. One linked through another provider configuration under that name is
// ErrProviderChanged and never falls through to registration. Otherwise, under RegistrationOpen, a
// new account is created whose email is id.Email, which must be verified, with the identity linked
// and its email stored as the verified provider email (O-04). It returns ErrRegistrationClosed, ErrEmailUnverified, ErrAccountExists
// when the email belongs to another account (never linked to it, D6), ErrInvalidIdentity for an
// empty or oversized identity, and httpx.ErrServiceUnavailable joined with a store failure. An
// unverified email is never looked up, so it reveals nothing about existing accounts.
func (d *Directory) SignIn(ctx context.Context, t core.TenantID, id ProviderIdentity) (core.Subject, error) {
	if !id.valid() {
		return core.Subject{}, ErrInvalidIdentity
	}
	if l, ok, err := d.linked(ctx, t, id); err != nil || ok {
		return d.resolve(ctx, t, id, l, err)
	}
	if d.registration != RegistrationOpen {
		return core.Subject{}, d.refuse(ctx, t, ErrRegistrationClosed)
	}
	email, ok := id.email()
	if !ok || !id.EmailVerified {
		return core.Subject{}, d.refuse(ctx, t, ErrEmailUnverified)
	}
	_, err := d.users.FindUser(ctx, t, email)
	switch {
	case err == nil:
		return core.Subject{}, d.refuse(ctx, t, ErrAccountExists)
	case !errors.Is(err, store.ErrNotFound):
		return core.Subject{}, unavailable(err)
	}
	a, err := d.accounts.Apply(ctx, identity.CreateVerified{
		Tenant: t,
		Email:  email,
		Federated: identity.FederatedIdentity{
			Provider: id.Provider, ProviderSubject: id.Subject, Authority: id.Authority, ProviderEmail: email, ProviderEmailVerified: true,
		},
	})
	if errors.Is(err, identity.ErrIdentifierTaken) {
		if l, ok, lerr := d.linked(ctx, t, id); lerr != nil || ok {
			return d.resolve(ctx, t, id, l, lerr)
		}
		return core.Subject{}, d.refuse(ctx, t, ErrAccountExists)
	}
	if err != nil {
		return core.Subject{}, unavailable(err)
	}
	_ = d.audit.Emit(ctx, event.UserRegistered, scopeOf(a.Subject), audit.Detail{}, nil, audit.A(event.KeyProvider, id.Provider))
	return a.Subject, nil
}

func (d *Directory) linked(ctx context.Context, t core.TenantID, id ProviderIdentity) (storefed.LinkedIdentity, bool, error) {
	l, err := d.links.FindLinked(ctx, t, id.key())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return storefed.LinkedIdentity{}, false, nil
	case err != nil:
		return storefed.LinkedIdentity{}, false, unavailable(err)
	case l.Subject.Tenant != t || l.Subject.IsZero() || l.Key != id.key():
		return storefed.LinkedIdentity{}, false, unavailable(errors.New("federationsvc: link of another tenant or identity"))
	}
	return l, true, nil
}

func (d *Directory) resolve(ctx context.Context, t core.TenantID, id ProviderIdentity, l storefed.LinkedIdentity, err error) (core.Subject, error) {
	switch {
	case err != nil:
		return core.Subject{}, err
	case l.Authority != id.Authority:
		_ = d.audit.Emit(ctx, event.LoginFailed, scopeOf(l.Subject), audit.Detail{Reason: ErrProviderChanged.Code()}, nil,
			audit.A(event.KeyProvider, id.Provider))
		return core.Subject{}, ErrProviderChanged
	}
	return l.Subject, nil
}

func (d *Directory) refuse(ctx context.Context, t core.TenantID, p *httpx.Problem) error {
	_ = d.audit.Emit(ctx, event.LoginFailed, audit.Scope{TenantID: t.String()}, audit.Detail{Reason: p.Code()}, nil)
	return p
}

// Link attaches id to sub, the subject a sensitive link request sealed at epoch. It is a no-op when
// id is already linked to sub under id.Authority; a link of sub made under another Authority is
// re-bound to id.Authority, which notifies sub like any new link. The link ends every session of
// sub (the epoch bump keeps no lineage).
// It returns ErrIdentityLinked when id is linked to another account, ErrEmailUnverified when sub's
// own email is not verified (§6.9.5), httpx.ErrUnauthenticated when sub is unusable or its epoch
// moved since the link began, ErrInvalidIdentity for an empty or oversized identity, and
// httpx.ErrServiceUnavailable joined with a store failure.
func (d *Directory) Link(ctx context.Context, sub core.Subject, epoch uint64, id ProviderIdentity) error {
	if !id.valid() {
		return ErrInvalidIdentity
	}
	l, ok, err := d.linked(ctx, sub.Tenant, id)
	switch {
	case err != nil:
		return err
	case ok && l.Subject != sub:
		return ErrIdentityLinked
	case ok && l.Authority == id.Authority:
		return nil
	}
	st, err := d.accounts.AccountState(ctx, sub)
	switch {
	case err != nil:
		return unavailable(err)
	case !st.Usable() || st.Epoch() != epoch:
		return httpx.ErrUnauthenticated
	case !st.EmailVerified():
		return ErrEmailUnverified
	}
	fed := identity.FederatedIdentity{Provider: id.Provider, ProviderSubject: id.Subject, Authority: id.Authority}
	if email, ok := id.email(); ok {
		fed.ProviderEmail, fed.ProviderEmailVerified = email, id.EmailVerified
	}
	_, err = d.accounts.Apply(ctx, identity.LinkFederated{Subject: sub, Identity: fed, Keep: uuid.Nil})
	switch {
	case errors.Is(err, identity.ErrIdentifierTaken):
		return ErrIdentityLinked
	case err != nil:
		return unavailable(err)
	}
	_ = d.audit.Emit(ctx, event.CredentialAdded, scopeOf(sub), audit.Detail{}, nil,
		audit.A(event.KeyFactor, core.FactorFederated.Code()), audit.A(event.KeyProvider, id.Provider))
	return nil
}

func scopeOf(sub core.Subject) audit.Scope {
	return audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()}
}
