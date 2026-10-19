package egauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/keys"
)

var (
	// ErrInvalidRequest is returned, joined with the reason, by a facade method given an incomplete
	// or out-of-bounds request: a nil user id, a malformed email, an unknown API-key kind, a zero
	// keys.Expiry. Nothing was changed.
	ErrInvalidRequest = errors.New("egauth: invalid facade request")
	// ErrFacadeUnavailable is returned by a facade method that needs a module, backend or store the
	// deployment leaves off: API keys without Modules.APIKeys, temporary passwords without
	// Modules.Password, key provisioning without TenantKeys, runtime providers without
	// OAuthModule.PerTenant.
	ErrFacadeUnavailable = errors.New("egauth: the deployment does not enable what this facade method needs")
	// ErrStorageUnavailable replaces a store, KEK or session-backend failure in the methods whose
	// errors are documented as safe to show the caller (Tenants.SetOAuthProvider): the cause, which
	// can name database users, hosts and addresses, goes to the event sink only. Retry later.
	ErrStorageUnavailable = errors.New("egauth: storage unavailable, retry later")
	// ErrProviderLinked is returned, joined with ErrInvalidRequest, by Tenants.SetOAuthProvider for a
	// spec whose Issuer, JWKSURL, TokenURL or UserInfoURL differ from those the provider name's
	// linked identities were made under: those links would stop resolving, and must not resolve to
	// another provider. Register the new provider under a new name and let users link it.
	ErrProviderLinked = errors.New("egauth: the provider name has identities linked under another configuration")
	// ErrTenantNotServed is returned by System for a tenant the deployment's Tenancy can never serve:
	// a non-zero tenant under SingleTenant, the zero tenant under multi-tenancy, or a tenant that
	// cannot form a host label under TenantBySubdomain.
	ErrTenantNotServed = errors.New("egauth: the deployment cannot serve this tenant")
)

const maxSystemReasonLen = 128

type claimSet struct {
	roles, scopes, groups []string
}

type facade struct {
	o        *owned
	storage  *Storage
	kek      kek.KEK
	admin    adminSpec
	reauth   time.Duration
	noReauth bool
	tenancy  tenancyKind
	keys     keySpec
	apiKeys  *APIKeyModule
	oauth    *OAuthModule
	password bool
	claims   func(ctx context.Context, s principal.Subject) (claimSet, error)
}

func (a *Auth[C]) facade() *facade {
	adm, _ := specOf(a.cfg.Admin.admin)
	_, ks := backendOf(a.cfg.Sessions)
	src := a.cfg.Claims
	return &facade{
		o:        a.owned,
		storage:  &a.cfg.Storage,
		kek:      a.cfg.KEK,
		admin:    adm,
		reauth:   a.cfg.Policy.ReauthWindow,
		noReauth: a.cfg.Insecure.NoReauthWindow != nil,
		tenancy:  tenancyOf(a.cfg.Tenancy),
		keys:     ks,
		apiKeys:  a.cfg.Modules.APIKeys,
		oauth:    a.cfg.Modules.OAuth,
		password: a.cfg.Modules.Password != nil,
		claims: func(ctx context.Context, s principal.Subject) (claimSet, error) {
			c, err := src.ClaimsFor(ctx, s)
			if err != nil {
				return claimSet{}, err
			}
			return claimSet{roles: slices.Clone(c.Roles), scopes: slices.Clone(c.Scopes), groups: slices.Clone(c.Groups)}, nil
		},
	}
}

type scope uint8

const (
	scopeAdmin scope = iota + 1
	scopeSelf
	scopeUser
	scopeSystem
)

type grant struct {
	system  bool
	tenant  core.TenantID
	subject core.Subject
	epoch   uint64
	claims  claimSet
}

func (f *facade) authorize(ctx context.Context, by principal.Caller, method string, tenant core.TenantID, target core.Subject, sc scope) (grant, error) {
	switch by.Kind() {
	case principal.CallerAPIKey:
		return grant{}, ErrAPIKeyCaller
	case principal.CallerResourceToken:
		return grant{}, ErrResourceTokenCaller
	case principal.CallerSystem:
		return f.authorizeSystem(ctx, by, method, tenant, sc)
	case principal.CallerSession:
		return f.authorizeSession(ctx, by, tenant, target, sc)
	}
	return grant{}, errors.Join(ErrForbidden, errors.New("egauth: the caller is not a session or system caller"))
}

func (f *facade) authorizeSystem(ctx context.Context, by principal.Caller, method string, tenant core.TenantID, sc scope) (grant, error) {
	err := f.systemRefusal(ctx, by, method, tenant, sc)
	_ = audit.Emit(ctx, f.o.events, event.SystemCallerUsed, audit.Scope{TenantID: by.Tenant().String()}, audit.Detail{Reason: by.Reason()}, err,
		audit.A(event.KeyEndpoint, method))
	if err != nil {
		return grant{}, err
	}
	return grant{system: true, tenant: tenant}, nil
}

func (f *facade) systemRefusal(ctx context.Context, by principal.Caller, method string, tenant core.TenantID, sc scope) error {
	switch {
	case principalctx.InRequest(ctx):
		return ErrSystemCallerInRequest
	case tenant != by.Tenant():
		return ErrTenantMismatch
	case sc == scopeSelf:
		return errors.Join(ErrForbidden, errors.New("egauth: "+method+" acts on the calling user, which a system caller does not have"))
	}
	return f.served(tenant)
}

func (f *facade) authorizeSession(ctx context.Context, by principal.Caller, tenant core.TenantID, target core.Subject, sc scope) (grant, error) {
	attrs, ok := by.Session()
	if !ok || attrs.IsZero() {
		return grant{}, errors.Join(ErrForbidden, errors.New("egauth: the session caller carries no session"))
	}
	if err := f.sessionLive(ctx, by); err != nil {
		return grant{}, err
	}
	if sc == scopeSystem {
		return grant{}, errors.Join(ErrForbidden, errors.New("egauth: only a system caller may run this method"))
	}
	sub := attrs.Subject()
	if tenant != by.Tenant() || sub.Tenant != tenant {
		return grant{}, ErrTenantMismatch
	}
	st, err := f.o.identity.AccountState(ctx, sub)
	switch {
	case err != nil:
		return grant{}, err
	case !st.Usable():
		return grant{}, errors.Join(ErrForbidden, errors.New("egauth: the calling account is not usable"))
	case st.Epoch() != attrs.Epoch():
		return grant{}, errors.Join(ErrReauthRequired, errors.New("egauth: the calling session predates a security change"))
	case st.MustChange() || attrs.MustChangePassword():
		return grant{}, errors.Join(ErrForbidden, errors.New("egauth: the caller must change their password first"))
	}
	claims, err := f.claims(ctx, sub)
	if err != nil {
		return grant{}, errors.Join(errors.New("egauth: reading the caller's claims"), err)
	}
	if needsAdmin(sc, sub, target) {
		if err := f.checkAdmin(claims); err != nil {
			return grant{}, err
		}
	}
	required, err := f.o.enrollment.MFARequired(ctx, sub)
	switch {
	case err != nil:
		return grant{}, errors.Join(errors.New("egauth: reading the caller's enrollment"), err)
	case required && !attrs.MultiFactor():
		return grant{}, errors.Join(ErrReauthRequired, errors.New("egauth: the caller enrolled a second factor this session lacks"))
	case !f.noReauth && !attrs.FreshWithin(f.reauth, f.o.clock.Now()):
		return grant{}, errors.Join(ErrReauthRequired, errors.New("egauth: the session is not fresh within the reauthentication window"))
	}
	return grant{tenant: tenant, subject: sub, epoch: st.Epoch(), claims: claims}, nil
}

func (f *facade) sessionLive(ctx context.Context, by principal.Caller) error {
	h, err := session.HandleOf(by)
	if err != nil {
		return errors.Join(ErrSessionEnded, err)
	}
	switch err := f.o.backend.Live(ctx, h); {
	case err == nil:
		return nil
	case errors.Is(err, session.ErrEnded):
		return errors.Join(ErrSessionEnded, err)
	default:
		return errors.Join(errors.New("egauth: checking the caller's session"), err)
	}
}

func needsAdmin(sc scope, caller, target core.Subject) bool {
	switch sc {
	case scopeSelf:
		return false
	case scopeUser:
		return target != caller
	}
	return true
}

func (f *facade) checkAdmin(c claimSet) error {
	if f.admin.kind != adminRole {
		return errors.Join(ErrForbidden, errors.New("egauth: the admin policy lets no session caller act on others"))
	}
	if !slices.Contains(c.roles, f.admin.role) {
		return errors.Join(ErrForbidden, errors.New("egauth: the caller lacks the admin role"))
	}
	return nil
}

func (f *facade) targetUser(by principal.Caller, user uuid.UUID) (core.Subject, error) {
	sub := core.Subject{Tenant: by.Tenant(), User: user}
	if sub.IsZero() {
		return core.Subject{}, errors.Join(ErrInvalidRequest, errors.New("egauth: the user id is nil"))
	}
	return sub, nil
}

func (f *facade) served(t core.TenantID) error {
	switch f.tenancy {
	case tenancySingle:
		if !t.IsZero() {
			return errors.Join(ErrTenantNotServed, errors.New("egauth: a single-tenant deployment serves the zero tenant only"))
		}
	case tenancySubdomain:
		if _, err := tenantHostLabel(t); err != nil {
			return errors.Join(ErrTenantNotServed, err)
		}
	default:
		if t.IsZero() {
			return errors.Join(ErrTenantNotServed, errors.New("egauth: a multi-tenant deployment never serves the zero tenant"))
		}
	}
	return nil
}

func checkSystemReason(reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > maxSystemReasonLen {
		return errors.Join(ErrInvalidRequest, errors.New("egauth: the system reason must be 1 to 128 bytes and not blank"))
	}
	for i := range len(reason) {
		if c := reason[i]; c < 0x20 || c > 0x7e {
			return errors.Join(ErrInvalidRequest, errors.New("egauth: the system reason must be printable ASCII"))
		}
	}
	return nil
}

func emitFor(ctx context.Context, f *facade, t event.Type, s core.Subject, reason string, attrs ...audit.Attr) {
	sc := audit.Scope{TenantID: s.Tenant.String()}
	if !s.IsZero() {
		sc.UserID = s.User.String()
	}
	_ = audit.Emit(ctx, f.o.events, t, sc, audit.Detail{Reason: reason}, nil, attrs...)
}

func (f *facade) tenantAlive(ctx context.Context, t core.TenantID) error {
	if f.keys.kind != keysTenant || !present(f.storage.Keys) {
		return nil
	}
	dead, err := f.storage.Keys.IsTombstoned(ctx, t)
	switch {
	case err != nil:
		return errors.Join(errors.New("egauth: reading the tenant tombstone"), err)
	case dead:
		return keys.ErrTenantTombstoned
	}
	return nil
}
