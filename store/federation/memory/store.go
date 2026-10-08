// Package memory provides an in-process federation.Store. It reports store.Ephemeral: provider specs
// are lost on restart and invisible to other instances.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
)

var _ federation.Store = (*Store)(nil)

const passwordProvider = "password"

// Links is the identity store the linked identities are read from. Links are written only by its
// CreateVerified, LinkFederated and UnlinkFederated mutations, so it must be the very identity store
// those mutations go to; *store/identity/memory.Store satisfies it.
type Links interface {
	GetUser(ctx context.Context, s principal.Subject) (identity.User, error)
	FindFederated(ctx context.Context, k identity.FederatedKey) (identity.FederatedLink, error)
	ListFederated(ctx context.Context, s principal.Subject) ([]identity.FederatedLink, error)
}

type providerRef struct {
	tenant principal.TenantID
	name   string
}

type linkRef struct {
	key federation.LinkKey
	at  int64
}

const sweepPerDelete = 2

type providerRow struct {
	spec federation.ProviderSpec
	seq  uint64
}

// Store is safe for concurrent use. Instants are kept to the microsecond like the SQL stores.
//
// Links live in the identity store, which owns them as the identities table does for the SQL store.
// DeleteForSubject and EraseTenant cannot delete them there, so they hide them instead: the links a
// subject holds when DeleteForSubject runs, and every link of the tenant made no later than
// EraseTenant by the store clock, which must be the identity store's clock. The identity store's own
// EraseUser and EraseTenant delete them for good.
//
// The hiding records stay bounded: EraseTenant drops the per-link records of the tenant, which its
// erasure instant already covers, and every DeleteForSubject re-reads a few hidden subjects from the
// identity store and forgets the links it no longer holds. What remains for good is one instant per
// erased tenant, like a tombstone.
type Store struct {
	clk       clock.Clock
	links     Links
	mu        sync.Mutex
	providers map[providerRef]*providerRow
	unlinked  map[principal.Subject]map[linkRef]struct{}
	erased    map[principal.TenantID]time.Time
	gen       uint64
	seq       uint64
}

// New returns an empty store that reads links from links and the wall clock.
func New(links Links) *Store { return NewWithClock(clock.Clock{}, links) }

// NewWithClock returns an empty store that reads links from links and the time from c; the
// composition root passes the library clock, the one the identity store reads. With a nil links
// every link read fails.
func NewWithClock(c clock.Clock, links Links) *Store {
	return &Store{
		clk:       c,
		links:     links,
		providers: map[providerRef]*providerRow{},
		unlinked:  map[principal.Subject]map[linkRef]struct{}{},
		erased:    map[principal.TenantID]time.Time{},
	}
}

func (s *Store) now() time.Time { return s.clk.Now().UTC().Truncate(time.Microsecond) }

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref := range s.providers {
		if ref.tenant == t {
			delete(s.providers, ref)
		}
	}
	if prev, ok := s.erased[t]; !ok || now.After(prev) {
		s.erased[t] = now
	}
	at := s.erased[t].UnixMicro()
	for sub, refs := range s.unlinked {
		if sub.Tenant != t {
			continue
		}
		for ref := range refs {
			if ref.at <= at {
				delete(refs, ref)
			}
		}
		if len(refs) == 0 {
			delete(s.unlinked, sub)
		}
	}
	s.gen++
	return nil
}

var (
	errInvalidSpec  = errors.New("federation: invalid provider spec")
	errInvalidLimit = errors.New("federation: limit must be positive")
	errInvalidSeal  = errors.New("federation: invalid reseal")
	errNoLinks      = errors.New("federation: the memory store has no identity store to read links from")
)

func checkSpec(p federation.ProviderSpec) error {
	if p.AADVersion != federation.AADVersionCurrent {
		return federation.ErrLegacyAADVersion
	}
	if p.Name == "" || len(p.SealedSecret) == 0 || !p.EmailVerification.Valid() {
		return errInvalidSpec
	}
	for _, sc := range p.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t\r\n") {
			return errInvalidSpec
		}
	}
	return nil
}

func nilIfEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return slices.Clone(in)
}

func cloneSpec(p federation.ProviderSpec) federation.ProviderSpec {
	p.SealedSecret = bytes.Clone(p.SealedSecret)
	p.Scopes = nilIfEmpty(p.Scopes)
	p.Domains = nilIfEmpty(p.Domains)
	return p
}

func (s *Store) PutProvider(ctx context.Context, p federation.ProviderSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkSpec(p); err != nil {
		return err
	}
	p = cloneSpec(p)
	p.UpdatedAt = s.now()
	ref := providerRef{p.Tenant, p.Name}
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.providers[ref]; ok {
		row.spec = p
		return nil
	}
	s.seq++
	s.providers[ref] = &providerRow{spec: p, seq: s.seq}
	return nil
}

func (s *Store) GetProvider(ctx context.Context, t principal.TenantID, name string) (federation.ProviderSpec, error) {
	if err := ctx.Err(); err != nil {
		return federation.ProviderSpec{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.providers[providerRef{t, name}]
	if !ok {
		return federation.ProviderSpec{}, store.ErrNotFound
	}
	return cloneSpec(row.spec), nil
}

func (s *Store) ListProviders(ctx context.Context, t principal.TenantID) ([]federation.ProviderSpec, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []federation.ProviderSpec{}
	for ref, row := range s.providers {
		if ref.tenant == t {
			out = append(out, cloneSpec(row.spec))
		}
	}
	slices.SortFunc(out, func(a, b federation.ProviderSpec) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

func (s *Store) DeleteProvider(ctx context.Context, t principal.TenantID, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, providerRef{t, name})
	return nil
}

func refOf(l identity.FederatedLink) linkRef {
	return linkRef{
		key: federation.LinkKey{Provider: l.Identity.Provider, ProviderSubject: l.Identity.ProviderSubject},
		at:  l.LinkedAt.UnixMicro(),
	}
}

func (s *Store) erasedCovers(l identity.FederatedLink) bool {
	at, ok := s.erased[l.Subject.Tenant]
	return ok && l.LinkedAt.UnixMicro() <= at.UnixMicro()
}

func (s *Store) hidden(l identity.FederatedLink) bool {
	if _, gone := s.unlinked[l.Subject][refOf(l)]; gone {
		return true
	}
	return s.erasedCovers(l)
}

func linked(l identity.FederatedLink) federation.LinkedIdentity {
	email := l.Identity.ProviderEmail.Value()
	return federation.LinkedIdentity{
		Subject:               l.Subject,
		Key:                   federation.LinkKey{Provider: l.Identity.Provider, ProviderSubject: l.Identity.ProviderSubject},
		ProviderEmail:         email,
		ProviderEmailVerified: l.Identity.ProviderEmailVerified && email != "",
		LinkedAt:              l.LinkedAt.UTC().Truncate(time.Microsecond),
	}
}

func (s *Store) FindLinked(ctx context.Context, t principal.TenantID, k federation.LinkKey) (federation.LinkedIdentity, error) {
	if err := ctx.Err(); err != nil {
		return federation.LinkedIdentity{}, err
	}
	if s.links == nil {
		return federation.LinkedIdentity{}, errNoLinks
	}
	if k.Provider == passwordProvider {
		return federation.LinkedIdentity{}, store.ErrNotFound
	}
	l, err := s.links.FindFederated(ctx, identity.FederatedKey{Tenant: t, Provider: k.Provider, ProviderSubject: k.ProviderSubject})
	if err != nil {
		return federation.LinkedIdentity{}, err
	}
	if l.Subject.Tenant != t || l.Identity.Provider != k.Provider || l.Identity.ProviderSubject != k.ProviderSubject {
		return federation.LinkedIdentity{}, store.ErrNotFound
	}
	u, err := s.links.GetUser(ctx, l.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return federation.LinkedIdentity{}, store.ErrNotFound
	}
	if err != nil {
		return federation.LinkedIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !u.DeletedAt.IsZero() || s.hidden(l) {
		return federation.LinkedIdentity{}, store.ErrNotFound
	}
	return linked(l), nil
}

func (s *Store) live(ctx context.Context, sub principal.Subject) ([]identity.FederatedLink, error) {
	if s.links == nil {
		return nil, errNoLinks
	}
	u, err := s.links.GetUser(ctx, sub)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !u.DeletedAt.IsZero() {
		return nil, nil
	}
	list, err := s.links.ListFederated(ctx, sub)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return list, err
}

func (s *Store) LinkedFor(ctx context.Context, sub principal.Subject) ([]federation.LinkedIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	list, err := s.live(ctx, sub)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []federation.LinkedIdentity{}
	for _, l := range list {
		if l.Subject != sub || l.Identity.Provider == passwordProvider || s.hidden(l) {
			continue
		}
		out = append(out, linked(l))
	}
	slices.SortFunc(out, func(a, b federation.LinkedIdentity) int {
		return cmp.Or(
			a.LinkedAt.Compare(b.LinkedAt),
			cmp.Compare(a.Key.Provider, b.Key.Provider),
			cmp.Compare(a.Key.ProviderSubject, b.Key.ProviderSubject),
		)
	})
	return out, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.links == nil {
		return errNoLinks
	}
	list, err := s.links.ListFederated(ctx, sub)
	if errors.Is(err, store.ErrNotFound) {
		list = nil
	} else if err != nil {
		return err
	}
	for _, other := range s.hide(sub, list) {
		s.forgetGone(ctx, other)
	}
	return nil
}

func (s *Store) hide(sub principal.Subject, list []identity.FederatedLink) []principal.Subject {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.unlinked[sub]
	for _, l := range list {
		if l.Subject != sub || s.erasedCovers(l) {
			continue
		}
		if refs == nil {
			refs = map[linkRef]struct{}{}
			s.unlinked[sub] = refs
		}
		refs[refOf(l)] = struct{}{}
	}
	s.gen++
	others := make([]principal.Subject, 0, sweepPerDelete)
	for other := range s.unlinked {
		if len(others) == sweepPerDelete {
			break
		}
		if other != sub {
			others = append(others, other)
		}
	}
	return others
}

func (s *Store) forgetGone(ctx context.Context, sub principal.Subject) {
	s.mu.Lock()
	gen := s.gen
	s.mu.Unlock()
	list, err := s.links.ListFederated(ctx, sub)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return
	}
	held := make(map[linkRef]struct{}, len(list))
	for _, l := range list {
		if l.Subject == sub {
			held[refOf(l)] = struct{}{}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return
	}
	refs := s.unlinked[sub]
	for ref := range refs {
		if _, ok := held[ref]; !ok {
			delete(refs, ref)
		}
	}
	if len(refs) == 0 {
		delete(s.unlinked, sub)
	}
	s.gen++
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, row := range s.providers {
		if row.spec.AADVersion == federation.AADVersionLegacy {
			n++
		}
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]federation.V016Row, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, after, err
	}
	if limit < 1 {
		return nil, after, errInvalidLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []*providerRow
	for _, row := range s.providers {
		if row.spec.AADVersion == federation.AADVersionLegacy && row.seq > after.Position() {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b *providerRow) int { return cmp.Compare(a.seq, b.seq) })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]federation.V016Row, 0, len(rows))
	cur := after
	for _, row := range rows {
		out = append(out, federation.V016Row{
			Ref:    federation.SealedRef{Tenant: row.spec.Tenant, Provider: row.spec.Name},
			Sealed: bytes.Clone(row.spec.SealedSecret),
		})
		cur = store.RestoreCursor(row.seq)
	}
	return out, cur, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r federation.Reseal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(r.Old) == 0 || len(r.New) == 0 || r.Ref.Provider == "" {
		return false, errInvalidSeal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.providers[providerRef{r.Ref.Tenant, r.Ref.Provider}]
	if !ok || !bytes.Equal(row.spec.SealedSecret, r.Old) {
		return false, nil
	}
	row.spec.SealedSecret = bytes.Clone(r.New)
	row.spec.AADVersion = federation.AADVersionCurrent
	return true, nil
}

func (s *Store) addV016(p federation.ProviderSpec) {
	p = cloneSpec(p)
	p.AADVersion = federation.AADVersionLegacy
	p.UpdatedAt = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := providerRef{p.Tenant, p.Name}
	if row, ok := s.providers[ref]; ok {
		row.spec = p
		return
	}
	s.seq++
	s.providers[ref] = &providerRow{spec: p, seq: s.seq}
}
