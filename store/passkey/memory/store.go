// Package memory provides an in-process passkey.Store. It reports store.Ephemeral: credentials are
// lost on restart and invisible to other instances, so it suits tests and single-process demos only.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/passkey"
)

var _ passkey.Store = (*Store)(nil)

type key struct {
	tenant principal.TenantID
	id     string
}

// Store is safe for concurrent use. Instants are kept to the microsecond like the SQL stores.
type Store struct {
	mu    sync.Mutex
	creds map[key]*passkey.Credential
}

// New returns an empty store.
func New() *Store { return &Store{creds: map[key]*passkey.Credential{}} }

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.creds {
		if k.tenant == t {
			delete(s.creds, k)
		}
	}
	return nil
}

func checkCredential(c passkey.Credential) error {
	if c.Subject.IsZero() {
		return errInvalid("subject")
	}
	if len(c.ID) == 0 || len(c.ID) > passkey.MaxCredentialIDLen {
		return errInvalid("credential id")
	}
	if len(c.PublicKey) == 0 {
		return errInvalid("public key")
	}
	if !c.Discoverable.Valid() || c.Discoverable == passkey.Legacy {
		return errInvalid("discoverable state")
	}
	return nil
}

type errInvalid string

func (e errInvalid) Error() string { return "passkey: invalid credential " + string(e) }

func truncate(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

func clone(c passkey.Credential) passkey.Credential {
	c.ID = bytes.Clone(c.ID)
	c.PublicKey = bytes.Clone(c.PublicKey)
	c.Data = bytes.Clone(c.Data)
	c.Transports = slices.Clone(c.Transports)
	c.CreatedAt = c.CreatedAt.UTC().Truncate(time.Microsecond)
	c.LastUsedAt = truncate(c.LastUsedAt)
	c.SuspendedAt = truncate(c.SuspendedAt)
	return c
}

func (s *Store) Save(ctx context.Context, c passkey.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkCredential(c); err != nil {
		return err
	}
	k := key{c.Subject.Tenant, string(c.ID)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.creds[k]; ok {
		return store.ErrConflict
	}
	v := clone(c)
	s.creds[k] = &v
	return nil
}

func (s *Store) List(ctx context.Context, sub principal.Subject) ([]passkey.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []passkey.Credential
	for _, c := range s.creds {
		if c.Subject == sub {
			out = append(out, clone(*c))
		}
	}
	slices.SortFunc(out, func(a, b passkey.Credential) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), bytes.Compare(a.ID, b.ID))
	})
	return out, nil
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, id passkey.CredentialID) (passkey.Credential, error) {
	if err := ctx.Err(); err != nil {
		return passkey.Credential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[key{t, string(id)}]
	if !ok {
		return passkey.Credential{}, store.ErrNotFound
	}
	return clone(*c), nil
}

func (s *Store) owned(sub principal.Subject, id passkey.CredentialID) (*passkey.Credential, bool) {
	c, ok := s.creds[key{sub.Tenant, string(id)}]
	if !ok || c.Subject != sub {
		return nil, false
	}
	return c, true
}

func (s *Store) Update(ctx context.Context, c passkey.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.Discoverable.Valid() {
		return errInvalid("discoverable state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.owned(c.Subject, c.ID)
	if !ok {
		return store.ErrNotFound
	}
	v := clone(c)
	cur.Nickname = v.Nickname
	cur.LastUsedAt = v.LastUsedAt
	cur.Transports = v.Transports
	cur.BackupEligible = v.BackupEligible
	cur.BackupState = v.BackupState
	if v.Discoverable != passkey.Legacy {
		cur.Discoverable = v.Discoverable
	}
	return nil
}

func (s *Store) UpdateSignCount(ctx context.Context, sub principal.Subject, id passkey.CredentialID, next uint32) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.owned(sub, id)
	if !ok {
		return false, store.ErrNotFound
	}
	if !cur.AcceptsSignCount(next) {
		return false, nil
	}
	cur.SignCount = next
	return true, nil
}

func (s *Store) Suspend(ctx context.Context, sub principal.Subject, id passkey.CredentialID, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.owned(sub, id)
	if !ok {
		return store.ErrNotFound
	}
	if cur.SuspendedAt == nil {
		cur.SuspendedAt = truncate(&at)
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, sub principal.Subject, id passkey.CredentialID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.owned(sub, id); !ok {
		return store.ErrNotFound
	}
	delete(s.creds, key{sub.Tenant, string(id)})
	return nil
}

func (s *Store) HasActive(ctx context.Context, sub principal.Subject) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.creds {
		if c.Subject == sub && c.Active() {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) AnyEnrolled(ctx context.Context) (bool, error) {
	n, err := s.CountEnrolled(ctx)
	return n > 0, err
}

func (s *Store) CountEnrolled(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	subjects := map[principal.Subject]struct{}{}
	for _, c := range s.creds {
		subjects[c.Subject] = struct{}{}
	}
	return int64(len(subjects)), nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.creds {
		if c.Subject == sub {
			delete(s.creds, k)
		}
	}
	return nil
}
