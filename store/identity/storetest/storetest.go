// Package storetest holds the conformance suite of identity.Store implementations.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// ErrInjected is the error a Hooks.Fail implementation makes the armed step return; Apply must
// return it, joined or not, and write nothing.
var ErrInjected = errors.New("storetest: injected failure")

// Hooks reach the state that the identity.Store contract cannot set, on the store under test. Every
// field is required.
type Hooks struct {
	// Age moves every instant stored for s d into the past, as if it had happened d earlier: the
	// created, due and done instants of its epoch-log and outbox rows, and the last failure and
	// locked-until of its password lockout. Row order and cursors are left as they are.
	Age func(t *testing.T, st identity.Store, s principal.Subject, d time.Duration)
	// Fail arms st so that step n (0-based) of its next Apply transaction, counting every statement
	// and the commit, returns ErrInjected, and returns the context that Apply is called with: an
	// implementation may arm st itself and return ctx, or carry the fault in the returned context.
	// The fault disarms once that transaction starts; an Apply with fewer steps succeeds.
	Fail func(t *testing.T, ctx context.Context, st identity.Store, n int) context.Context
	// Unverified inserts account s with an unverified email, as v0.16 left one; no mutation creates
	// such an account.
	Unverified func(t *testing.T, st identity.Store, s principal.Subject, email identity.Identifier)
}

var hooks sync.Map

// Use hands Run, for t and its subtests, the hooks of the store implementation. Call it before Run
// on the same t.
func Use(t *testing.T, h Hooks) {
	t.Helper()
	if h.Age == nil || h.Fail == nil || h.Unverified == nil {
		t.Fatal("storetest: every Hooks field is required")
	}
	hooks.Store(t, h)
	t.Cleanup(func() { hooks.Delete(t) })
}

// Run exercises the identity.Store contract against stores returned by newStore; each subtest gets
// a fresh, empty store. Time comes from the wall clock; the store's clock must agree with it within
// a minute. Run fails t unless Use was called on it.
func Run(t *testing.T, newStore func(*testing.T) identity.Store) {
	t.Helper()
	v, ok := hooks.Load(t)
	if !ok {
		t.Fatal("storetest: call Use(t, hooks) before Run")
	}
	h := v.(Hooks)
	suites := map[string]func(*harness){
		"Base":                   baseSuite,
		"CreateVerified":         createVerified,
		"Lookups":                lookups,
		"MutationsTouchOwnState": touchOwnState,
		"MarkEmailVerified":      markEmailVerified,
		"ApplyRefusals":          applyRefusals,
		"IdentifierUniqueness":   identifierUniqueness,
		"FederatedLinks":         federatedLinks,
		"EffectsAreAtomic":       effectsAreAtomic,
		"ApplyEffects":           applyEffects,
		"EpochFeed":              epochFeed,
		"EpochFeedBackdated":     epochFeedBackdated,
		"EpochFeedConcurrent":    epochFeedConcurrent,
		"CurrentEpoch":           currentEpoch,
		"PasswordLockout":        passwordLockout,
		"Outbox":                 outbox,
		"EraseUser":              eraseUser,
		"EraseTenant":            eraseTenant,
		"ReapExpired":            reapExpired,
	}
	for _, name := range slices.Sorted(maps.Keys(suites)) {
		t.Run(name, func(t *testing.T) {
			suites[name](&harness{t: t, st: newStore(t), h: h, ctx: context.Background()})
		})
	}
}

type harness struct {
	t   *testing.T
	st  identity.Store
	h   Hooks
	ctx context.Context
}

const (
	recent     = time.Minute
	hour       = time.Hour
	goroutines = 16
)

var counter atomic.Uint64

func now() time.Time { return clock.Clock{}.Now() }

func next() uint64 { return counter.Add(1) }

func (h *harness) tenant(name string) principal.TenantID {
	h.t.Helper()
	if name == "" {
		return principal.TenantID{}
	}
	id, err := principal.ParseTenantID(name)
	require.NoError(h.t, err)
	return id
}

func (h *harness) email() identity.Identifier {
	return h.ident(identity.IdentifierEmail, fmt.Sprintf("user%d@example.com", next()))
}

func (h *harness) recovery() identity.Identifier {
	return h.ident(identity.IdentifierRecoveryEmail, fmt.Sprintf("backup%d@example.org", next()))
}

func (h *harness) phone() identity.Identifier {
	return h.ident(identity.IdentifierPhone, fmt.Sprintf("+1555%07d", next()%10_000_000))
}

func (h *harness) ident(k identity.IdentifierKind, v string) identity.Identifier {
	h.t.Helper()
	id, err := identity.NewIdentifier(k, v)
	require.NoError(h.t, err)
	return id
}

func phc() identity.PasswordHash {
	return identity.NewPasswordHash(fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$h%d", next()))
}

func (h *harness) federated(provider string) identity.FederatedIdentity {
	return identity.FederatedIdentity{
		Provider:              provider,
		ProviderSubject:       fmt.Sprintf("sub-%d", next()),
		ProviderEmail:         h.email(),
		ProviderEmailVerified: true,
	}
}

func (h *harness) apply(m identity.Mutation) identity.Applied {
	h.t.Helper()
	a, err := h.st.Apply(h.ctx, m)
	require.NoError(h.t, err, "apply %T", m)
	return a
}

func (h *harness) create(t principal.TenantID) principal.Subject {
	h.t.Helper()
	return h.apply(identity.CreateVerified{Tenant: t, Email: h.email(), PHC: phc()}).Subject
}

func (h *harness) full(t principal.TenantID) principal.Subject {
	h.t.Helper()
	s := h.apply(identity.CreateVerified{
		Tenant: t, Email: h.email(), PHC: phc(), MustChange: true, Federated: h.federated("google"),
	}).Subject
	h.apply(identity.SetPhone{Subject: s, Phone: h.phone()})
	h.apply(identity.SetRecoveryEmail{Subject: s, RecoveryEmail: h.recovery()})
	h.apply(identity.LinkFederated{Subject: s, Identity: h.federated("github")})
	h.apply(identity.SetDisabledState{Subject: s, Disable: true})
	_, err := h.st.RecordPasswordFailure(h.ctx, s, identity.LockoutPolicy{Threshold: 10, Window: time.Hour})
	require.NoError(h.t, err)
	return s
}

func (h *harness) unverifiedFull(t principal.TenantID) principal.Subject {
	h.t.Helper()
	s := newSubject(t)
	h.h.Unverified(h.t, h.st, s, h.email())
	h.apply(identity.SetPassword{Subject: s, PHC: phc(), Reason: identity.RotationTemporaryPassword})
	h.apply(identity.LinkFederated{Subject: s, Identity: h.federated("google")})
	h.apply(identity.LinkFederated{Subject: s, Identity: h.federated("github")})
	h.apply(identity.SetPhone{Subject: s, Phone: h.phone()})
	h.apply(identity.SetRecoveryEmail{Subject: s, RecoveryEmail: h.recovery()})
	h.apply(identity.SetDisabledState{Subject: s, Disable: true})
	_, err := h.st.RecordPasswordFailure(h.ctx, s, identity.LockoutPolicy{Threshold: 10, Window: time.Hour})
	require.NoError(h.t, err)
	return s
}

type account struct {
	User     identity.User
	Password *passwordState
	Links    []identity.FederatedLink
}

type passwordState struct {
	PHC            string
	ChangedAt      time.Time
	FailedAttempts int
	LockedUntil    time.Time
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

func (h *harness) account(s principal.Subject) account {
	h.t.Helper()
	u, err := h.st.GetUser(h.ctx, s)
	require.NoError(h.t, err)
	for _, p := range []*time.Time{&u.EmailVerifiedAt, &u.PhoneVerifiedAt, &u.RecoveryEmailVerifiedAt, &u.DisabledAt, &u.DeletedAt, &u.CreatedAt} {
		*p = utc(*p)
	}
	out := account{User: u}
	pw, err := h.st.GetPassword(h.ctx, s)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		require.NoError(h.t, err)
	default:
		require.Equal(h.t, s, pw.Subject)
		out.Password = &passwordState{PHC: pw.PHC.PHC(), ChangedAt: utc(pw.ChangedAt), FailedAttempts: pw.FailedAttempts, LockedUntil: utc(pw.LockedUntil)}
	}
	links, err := h.st.ListFederated(h.ctx, s)
	require.NoError(h.t, err)
	for _, l := range links {
		l.LinkedAt = utc(l.LinkedAt)
		out.Links = append(out.Links, l)
	}
	sortLinks(out.Links)
	return out
}

func sortLinks(l []identity.FederatedLink) {
	slices.SortFunc(l, func(a, b identity.FederatedLink) int {
		return strings.Compare(a.Identity.Provider+"\x00"+a.Identity.ProviderSubject, b.Identity.Provider+"\x00"+b.Identity.ProviderSubject)
	})
}

func (h *harness) recent(at time.Time, what string) {
	h.t.Helper()
	require.False(h.t, at.IsZero(), "%s must be set", what)
	require.WithinDuration(h.t, now(), at, recent, "%s must come from the store clock", what)
}

func (h *harness) epoch(s principal.Subject) uint64 {
	h.t.Helper()
	e, err := h.st.CurrentEpoch(h.ctx, s)
	require.NoError(h.t, err)
	return e
}

func (h *harness) feed(c store.Cursor) ([]identity.EpochChange, store.Cursor) {
	h.t.Helper()
	var all []identity.EpochChange
	for {
		got, nc, err := h.st.EpochsChangedSince(h.ctx, c)
		require.NoError(h.t, err)
		require.False(h.t, c.After(nc), "a cursor never moves backwards")
		if len(got) == 0 {
			require.Equal(h.t, c, nc, "an empty page keeps the cursor")
			return all, c
		}
		require.True(h.t, nc.After(c), "a non-empty page advances the cursor")
		all = append(all, got...)
		c = nc
	}
}

func (h *harness) pending() []identity.OutboxItem {
	h.t.Helper()
	got, err := h.st.PendingOutbox(h.ctx, 100_000)
	require.NoError(h.t, err)
	for i := range got {
		got[i] = normItem(got[i])
	}
	return got
}

func normItem(it identity.OutboxItem) identity.OutboxItem {
	it.NextAttemptAt = utc(it.NextAttemptAt)
	it.CreatedAt = utc(it.CreatedAt)
	return it
}

func (h *harness) ackAll(s principal.Subject, except ...identity.Component) {
	h.t.Helper()
	for _, it := range h.pending() {
		if it.Subject == s && !slices.Contains(except, it.Component) {
			require.NoError(h.t, h.st.AckOutbox(h.ctx, it.ID))
		}
	}
}

func newSubject(t principal.TenantID) principal.Subject {
	return principal.Subject{Tenant: t, User: uuid.New()}
}

func baseSuite(h *harness) {
	require.NoError(h.t, h.st.Ping(h.ctx))
	require.True(h.t, h.st.Durability().Valid())
	n, err := h.st.ReapExpired(h.ctx)
	require.NoError(h.t, err)
	require.Zero(h.t, n)
	require.NoError(h.t, h.st.EraseTenant(h.ctx, h.tenant("empty")))
}
