package egauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// Accounts administers the accounts of the caller's tenant. Every method needs a System caller or a
// live session caller (ErrSessionEnded otherwise) allowed by Config.Admin, fresh within
// SessionPolicy.ReauthWindow and multi-factor when its subject enrolled a second factor;
// RevokeSessions alone also lets a session caller act on itself. Disable, Enable, Delete and
// SetTemporaryPassword are applied by the identity service the auth endpoints use, which bumps the
// security epoch, queues the lifecycle outbox and notifies the owner; RevokeSessions and UnlockMFA
// act on the session backend and the MFA store directly, with no epoch bump, outbox row or notice.
// A user id of another tenant is never reached: the target is always the caller's tenant.
type Accounts struct {
	f *facade
}

// Accounts returns the account administration facade.
func (a *Auth[C]) Accounts() *Accounts {
	return &Accounts{f: a.facade()}
}

// CreateAccountRequest describes an account an administrator creates. Its email is marked verified
// without any proof of ownership, so the caller must know the address belongs to the intended
// user: magic links, login codes and password resets reach it at once. With TemporaryPassword the
// library generates a password the user must change at the first sign-in, and Modules.Password is
// required; without it the account has no password and signs in through the other enabled modules
// or a password reset.
type CreateAccountRequest struct {
	Email             string
	TemporaryPassword bool
}

// CreatedAccount is the account Accounts.Create made. TemporaryPassword is zero unless requested.
type CreatedAccount struct {
	Subject           principal.Subject
	TemporaryPassword TemporaryPassword
}

// TemporaryPassword is a library-generated password, shown once to whoever hands it to the user.
// It renders as REDACTED under fmt, slog and JSON; only Reveal returns it.
type TemporaryPassword struct {
	v *string
}

// Reveal returns the plaintext password; never log or persist it.
func (p TemporaryPassword) Reveal() string {
	if p.v == nil {
		return ""
	}
	return *p.v
}

func (p TemporaryPassword) IsZero() bool { return p.v == nil }

func (p TemporaryPassword) String() string { return "REDACTED" }

func (p TemporaryPassword) GoString() string { return "egauth.TemporaryPassword{REDACTED}" }

func (p TemporaryPassword) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

func (p TemporaryPassword) LogValue() slog.Value { return slog.StringValue(p.String()) }

func (p TemporaryPassword) MarshalJSON() ([]byte, error) { return []byte(`"REDACTED"`), nil }

const (
	tempPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	tempPasswordGroups   = 4
	tempPasswordGroupLen = 6
	tempPasswordAttempts = 3
)

// Create creates an account with a verified email in the caller's tenant. It returns
// ErrInvalidRequest for a malformed email, ErrFacadeUnavailable for a TemporaryPassword without
// Modules.Password, identity.ErrIdentifierTaken when a live account of the tenant owns it, and,
// under TenantKeys, keys.ErrTenantTombstoned for an erased tenant: an account created while
// Tenants.Erase runs is deleted again before the error returns.
func (x *Accounts) Create(ctx context.Context, by principal.Caller, req CreateAccountRequest) (CreatedAccount, error) {
	g, err := x.f.authorize(ctx, by, "Accounts.Create", by.Tenant(), core.Subject{}, scopeAdmin)
	if err != nil {
		return CreatedAccount{}, err
	}
	if req.TemporaryPassword {
		if err := x.passwordModule(); err != nil {
			return CreatedAccount{}, err
		}
	}
	email, err := identitysvc.NormalizeAs(identity.IdentifierEmail, req.Email)
	if err != nil {
		return CreatedAccount{}, errors.Join(ErrInvalidRequest, err)
	}
	if err := x.f.tenantAlive(ctx, g.tenant); err != nil {
		return CreatedAccount{}, err
	}
	m := identity.CreateVerified{Tenant: g.tenant, Email: email}
	var tp TemporaryPassword
	if req.TemporaryPassword {
		tp, m.PHC, err = x.temporaryPassword(ctx)
		if err != nil {
			return CreatedAccount{}, err
		}
		m.MustChange = true
	}
	applied, err := x.f.o.identity.Apply(ctx, m)
	if err != nil {
		return CreatedAccount{}, err
	}
	if err := x.f.tenantAlive(ctx, g.tenant); err != nil {
		if _, undo := x.f.o.identity.Apply(ctx, identity.Tombstone{Subject: applied.Subject}); undo != nil {
			return CreatedAccount{}, errors.Join(err, undo)
		}
		return CreatedAccount{}, err
	}
	emitFor(ctx, x.f, event.UserRegistered, applied.Subject, "admin_created")
	return CreatedAccount{Subject: applied.Subject, TemporaryPassword: tp}, nil
}

// Disable suspends the account: every session ends and its API keys stop working until Enable.
// Unknown or deleted users return store.ErrNotFound or identity.ErrTombstoned.
func (x *Accounts) Disable(ctx context.Context, by principal.Caller, user uuid.UUID) error {
	return x.apply(ctx, by, "Accounts.Disable", user, event.AccountDisabled, func(s core.Subject) identity.Mutation {
		return identity.SetDisabledState{Subject: s, Disable: true}
	})
}

// Enable lifts a suspension; sessions ended by Disable stay ended.
func (x *Accounts) Enable(ctx context.Context, by principal.Caller, user uuid.UUID) error {
	return x.apply(ctx, by, "Accounts.Enable", user, event.AccountEnabled, func(s core.Subject) identity.Mutation {
		return identity.SetDisabledState{Subject: s}
	})
}

// Delete tombstones the account; its factors, keys and sessions are erased by the lifecycle outbox
// and Hooks.AccountDeleted runs before the row is removed.
func (x *Accounts) Delete(ctx context.Context, by principal.Caller, user uuid.UUID) error {
	return x.apply(ctx, by, "Accounts.Delete", user, event.AccountDeleted, func(s core.Subject) identity.Mutation {
		return identity.Tombstone{Subject: s}
	})
}

// SetTemporaryPassword replaces the user's password with a generated one the user must change at
// the next sign-in; every session of the user ends and the owner is notified. It returns
// ErrFacadeUnavailable without Modules.Password, whose sign-in alone accepts the password, and
// store.ErrNotFound for an unknown or deleted user.
func (x *Accounts) SetTemporaryPassword(ctx context.Context, by principal.Caller, user uuid.UUID) (TemporaryPassword, error) {
	sub, g, err := x.live(ctx, by, "Accounts.SetTemporaryPassword", user, scopeAdmin)
	if err != nil {
		return TemporaryPassword{}, err
	}
	if err := x.passwordModule(); err != nil {
		return TemporaryPassword{}, err
	}
	tp, phc, err := x.temporaryPassword(ctx)
	if err != nil {
		return TemporaryPassword{}, err
	}
	if _, err := x.f.o.identity.Apply(ctx, identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationTemporaryPassword}); err != nil {
		return TemporaryPassword{}, err
	}
	emitFor(ctx, x.f, event.PasswordChanged, sub, systemOrAdmin(g), audit.A(event.KeyRotationReason, identity.RotationTemporaryPassword.String()))
	return tp, nil
}

// UnlockMFA clears the TOTP and recovery-code lockouts of the user, so a locked-out user can verify
// a second factor again at once. It returns store.ErrNotFound for an unknown or deleted user.
func (x *Accounts) UnlockMFA(ctx context.Context, by principal.Caller, user uuid.UUID) error {
	sub, _, err := x.live(ctx, by, "Accounts.UnlockMFA", user, scopeAdmin)
	if err != nil {
		return err
	}
	if err := x.f.storage.MFA.ResetTOTPAttempts(ctx, sub); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := x.f.storage.MFA.ResetRecoveryAttempts(ctx, sub); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	_ = audit.MFAUnlocked(ctx, x.f.o.events, audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()})
	return nil
}

// RevokeSessions ends every session of the user, like /logout-everywhere; a session caller may
// revoke its own sessions without the admin role. It returns store.ErrNotFound for an unknown or
// deleted user.
func (x *Accounts) RevokeSessions(ctx context.Context, by principal.Caller, user uuid.UUID) error {
	sub, _, err := x.live(ctx, by, "Accounts.RevokeSessions", user, scopeUser)
	if err != nil {
		return err
	}
	if err := x.f.o.backend.OnDisabled(ctx, lifecycle.AccountEvent{Subject: sub}); err != nil {
		return err
	}
	emitFor(ctx, x.f, event.Logout, sub, "revoke_sessions")
	return nil
}

func (x *Accounts) apply(ctx context.Context, by principal.Caller, method string, user uuid.UUID, t event.Type, m func(core.Subject) identity.Mutation) error {
	if _, err := x.f.authorize(ctx, by, method, by.Tenant(), core.Subject{}, scopeAdmin); err != nil {
		return err
	}
	sub, err := x.f.targetUser(by, user)
	if err != nil {
		return err
	}
	if _, err := x.f.o.identity.Apply(ctx, m(sub)); err != nil {
		return err
	}
	emitFor(ctx, x.f, t, sub, "")
	return nil
}

func (x *Accounts) live(ctx context.Context, by principal.Caller, method string, user uuid.UUID, sc scope) (core.Subject, grant, error) {
	sub, invalid := x.f.targetUser(by, user)
	g, err := x.f.authorize(ctx, by, method, by.Tenant(), sub, sc)
	switch {
	case err != nil:
		return core.Subject{}, grant{}, err
	case invalid != nil:
		return core.Subject{}, grant{}, invalid
	}
	st, err := x.f.o.identity.AccountState(ctx, sub)
	switch {
	case err != nil:
		return core.Subject{}, grant{}, err
	case !st.Exists() || st.Deleted():
		return core.Subject{}, grant{}, store.ErrNotFound
	}
	return sub, g, nil
}

func (x *Accounts) passwordModule() error {
	if !x.f.password {
		return errors.Join(ErrFacadeUnavailable, errors.New("egauth: temporary passwords need Modules.Password"))
	}
	return nil
}

func (x *Accounts) temporaryPassword(ctx context.Context) (TemporaryPassword, identity.PasswordHash, error) {
	var last error
	for range tempPasswordAttempts {
		pw, err := generatePassword()
		if err != nil {
			return TemporaryPassword{}, identity.PasswordHash{}, err
		}
		phc, err := x.f.o.identity.AcceptPassword(ctx, pw)
		if err == nil {
			return TemporaryPassword{v: &pw}, phc, nil
		}
		last = err
	}
	return TemporaryPassword{}, identity.PasswordHash{}, errors.Join(errors.New("egauth: the password policy refused every generated temporary password"), last)
}

func generatePassword() (string, error) {
	limit := 256 - 256%len(tempPasswordAlphabet)
	for {
		var sb strings.Builder
		n := 0
		for n < tempPasswordGroups*tempPasswordGroupLen {
			b := make([]byte, tempPasswordGroups*tempPasswordGroupLen)
			if _, err := rand.Read(b); err != nil {
				return "", errors.Join(errors.New("egauth: generating a temporary password"), err)
			}
			for _, c := range b {
				if int(c) >= limit || n == tempPasswordGroups*tempPasswordGroupLen {
					continue
				}
				if n > 0 && n%tempPasswordGroupLen == 0 {
					sb.WriteByte('-')
				}
				sb.WriteByte(tempPasswordAlphabet[int(c)%len(tempPasswordAlphabet)])
				n++
			}
		}
		pw := sb.String()
		if strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ") && strings.ContainsAny(pw, "abcdefghijkmnopqrstuvwxyz") && strings.ContainsAny(pw, "23456789") {
			return pw, nil
		}
	}
}

func systemOrAdmin(g grant) string {
	if g.system {
		return "system"
	}
	return "admin"
}
