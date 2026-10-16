// Package memory provides an in-process identity.Store. It reports store.Ephemeral: accounts are
// lost on restart and invisible to other instances.
package memory

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

var _ identity.Store = (*Store)(nil)

const passwordProvider = "password"

const feedPage = 1000

type password struct {
	phc         identity.PasswordHash
	changedAt   time.Time
	failed      int
	lockedUntil time.Time
	lastFailure time.Time
	mustChange  bool
}

type account struct {
	user     identity.User
	password *password
	links    []identity.FederatedLink
}

func (a *account) clone() *account {
	c := &account{user: a.user, links: slices.Clone(a.links)}
	if a.password != nil {
		p := *a.password
		c.password = &p
	}
	return c
}

func (a *account) view() identity.User {
	u := a.user
	u.MustChange = a.password != nil && a.password.mustChange
	return u
}

type epochRow struct {
	seq    uint64
	change identity.EpochChange
	at     time.Time
}

type outboxRow struct {
	item identity.OutboxItem
	done time.Time
}

// Store is safe for concurrent use. Like the SQL stores, it keeps instants to the microsecond, in
// UTC.
type Store struct {
	clk       clock.Clock
	mu        sync.Mutex
	accounts  map[principal.Subject]*account
	epochSeq  uint64
	epochs    []epochRow
	outboxSeq int64
	outbox    []*outboxRow
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{clk: c, accounts: map[principal.Subject]*account{}}
}

func (s *Store) now() time.Time { return instant(s.clk.Now()) }

func instant(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Microsecond)
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.accounts {
		if k.Tenant == t {
			delete(s.accounts, k)
		}
	}
	s.epochs = slices.DeleteFunc(s.epochs, func(r epochRow) bool { return r.change.Subject.Tenant == t })
	s.outbox = slices.DeleteFunc(s.outbox, func(r *outboxRow) bool { return r.item.Subject.Tenant == t })
	return nil
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-identity.Retention)
	before := len(s.epochs) + len(s.outbox)
	s.epochs = slices.DeleteFunc(s.epochs, func(r epochRow) bool { return r.at.Before(cutoff) })
	s.outbox = slices.DeleteFunc(s.outbox, func(r *outboxRow) bool { return !r.done.IsZero() && r.done.Before(cutoff) })
	return int64(before - len(s.epochs) - len(s.outbox)), nil
}

func (s *Store) existing(sub principal.Subject) (*account, error) {
	a := s.accounts[sub]
	if a == nil {
		return nil, store.ErrNotFound
	}
	return a, nil
}

func (s *Store) GetUser(ctx context.Context, sub principal.Subject) (identity.User, error) {
	if err := ctx.Err(); err != nil {
		return identity.User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return identity.User{}, err
	}
	return a.view(), nil
}

func (s *Store) FindUser(ctx context.Context, t principal.TenantID, id identity.Identifier) (identity.User, error) {
	if err := ctx.Err(); err != nil {
		return identity.User{}, err
	}
	if id.Kind() != identity.IdentifierEmail && id.Kind() != identity.IdentifierPhone {
		return identity.User{}, errors.Join(identity.ErrInvalidIdentifier, errors.New("only an email or a phone finds an account"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.owner(t, id, uuid.Nil); a != nil {
		return a.view(), nil
	}
	return identity.User{}, store.ErrNotFound
}

func (s *Store) owner(t principal.TenantID, id identity.Identifier, except uuid.UUID) *account {
	for k, a := range s.accounts {
		if k.Tenant != t || k.User == except || !a.user.DeletedAt.IsZero() {
			continue
		}
		switch id.Kind() {
		case identity.IdentifierEmail:
			if a.user.Email == id {
				return a
			}
		case identity.IdentifierPhone:
			if a.user.Phone == id {
				return a
			}
		}
	}
	return nil
}

func (s *Store) linkOwner(t principal.TenantID, provider, subject string) (*account, bool) {
	for k, a := range s.accounts {
		if k.Tenant != t {
			continue
		}
		for _, l := range a.links {
			if l.Identity.Provider == provider && l.Identity.ProviderSubject == subject {
				return a, true
			}
		}
	}
	return nil, false
}

func (s *Store) GetPassword(ctx context.Context, sub principal.Subject) (identity.PasswordCredential, error) {
	if err := ctx.Err(); err != nil {
		return identity.PasswordCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return identity.PasswordCredential{}, err
	}
	if a.password == nil {
		return identity.PasswordCredential{}, store.ErrNotFound
	}
	p := a.password
	return identity.PasswordCredential{
		Subject: sub, PHC: p.phc, ChangedAt: p.changedAt, FailedAttempts: p.failed, LockedUntil: p.lockedUntil,
	}, nil
}

func checkPolicy(p identity.LockoutPolicy) error {
	if p.Threshold <= 0 || p.Window <= 0 {
		return errors.Join(identity.ErrInvalidMutation, errors.New("lockout threshold and window must be positive"))
	}
	return nil
}

func (s *Store) RecordPasswordFailure(ctx context.Context, sub principal.Subject, p identity.LockoutPolicy) (identity.Lockout, error) {
	if err := ctx.Err(); err != nil {
		return identity.Lockout{}, err
	}
	if err := checkPolicy(p); err != nil {
		return identity.Lockout{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return identity.Lockout{}, err
	}
	pw := a.password
	if pw == nil {
		return identity.Lockout{}, store.ErrNotFound
	}
	now := s.now()
	switch {
	case !pw.lockedUntil.IsZero() && !pw.lockedUntil.After(now):
		pw.failed, pw.lockedUntil = 0, time.Time{}
	case pw.lockedUntil.IsZero() && !pw.lastFailure.IsZero() && !pw.lastFailure.Add(p.Window).After(now):
		pw.failed = 0
	}
	pw.failed++
	pw.lastFailure = now
	just := false
	if pw.lockedUntil.IsZero() && pw.failed >= p.Threshold {
		pw.lockedUntil, just = instant(now.Add(p.Window)), true
	}
	return identity.Lockout{FailedAttempts: pw.failed, LockedUntil: pw.lockedUntil, JustLocked: just}, nil
}

func (s *Store) ResetPasswordFailures(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return err
	}
	if a.password == nil {
		return store.ErrNotFound
	}
	a.password.failed, a.password.lockedUntil, a.password.lastFailure = 0, time.Time{}, time.Time{}
	return nil
}

func (s *Store) FindFederated(ctx context.Context, k identity.FederatedKey) (identity.FederatedLink, error) {
	if err := ctx.Err(); err != nil {
		return identity.FederatedLink{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.linkOwner(k.Tenant, k.Provider, k.ProviderSubject)
	if !ok || !a.user.DeletedAt.IsZero() {
		return identity.FederatedLink{}, store.ErrNotFound
	}
	for _, l := range a.links {
		if l.Identity.Provider == k.Provider && l.Identity.ProviderSubject == k.ProviderSubject {
			return l, nil
		}
	}
	return identity.FederatedLink{}, store.ErrNotFound
}

func (s *Store) ListFederated(ctx context.Context, sub principal.Subject) ([]identity.FederatedLink, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return nil, err
	}
	return slices.Clone(a.links), nil
}

// ListFederatedTo returns every link to provider held by a live account of tenant t, for
// federation.Store.HasLinksOutside.
func (s *Store) ListFederatedTo(ctx context.Context, t principal.TenantID, provider string) ([]identity.FederatedLink, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []identity.FederatedLink
	for k, a := range s.accounts {
		if k.Tenant != t || !a.user.DeletedAt.IsZero() {
			continue
		}
		for _, l := range a.links {
			if l.Identity.Provider == provider {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func (s *Store) CurrentEpoch(ctx context.Context, sub principal.Subject) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return 0, err
	}
	return a.user.SecurityEpoch, nil
}

func (s *Store) EpochsChangedSince(ctx context.Context, c store.Cursor) ([]identity.EpochChange, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, c, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []identity.EpochChange
	last := c.Position()
	for _, r := range s.epochs {
		if r.seq <= c.Position() {
			continue
		}
		if len(out) == feedPage {
			break
		}
		out = append(out, r.change)
		last = r.seq
	}
	return out, store.RestoreCursor(last), nil
}

func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]identity.OutboxItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []identity.OutboxItem
	for _, r := range s.outbox {
		if len(out) >= limit {
			break
		}
		if r.done.IsZero() && !r.item.NextAttemptAt.After(now) {
			out = append(out, r.item)
		}
	}
	return out, nil
}

func (s *Store) row(id int64) *outboxRow {
	i, ok := slices.BinarySearchFunc(s.outbox, id, func(r *outboxRow, id int64) int {
		switch {
		case r.item.ID < id:
			return -1
		case r.item.ID > id:
			return 1
		}
		return 0
	})
	if !ok {
		return nil
	}
	return s.outbox[i]
}

func (s *Store) AckOutbox(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.row(id)
	if r == nil {
		return store.ErrNotFound
	}
	if r.done.IsZero() {
		r.done = s.now()
	}
	return nil
}

func (s *Store) FailOutbox(ctx context.Context, id int64, next time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.row(id)
	if r == nil {
		return store.ErrNotFound
	}
	if !r.done.IsZero() {
		return nil
	}
	r.item.Attempts++
	r.item.NextAttemptAt = instant(next)
	return nil
}

func (s *Store) EraseUser(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.existing(sub)
	if err != nil {
		return err
	}
	if a.user.DeletedAt.IsZero() {
		return identity.ErrNotTombstoned
	}
	for _, r := range s.outbox {
		if r.item.Subject == sub && r.done.IsZero() && r.item.Component != identity.ComponentIdentity {
			return errors.Join(store.ErrConflict, errors.New("identity: an outbox row of the subject is not done"))
		}
	}
	delete(s.accounts, sub)
	return nil
}
