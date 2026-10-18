// Package memory provides an in-process ceremony.Store. It reports store.Ephemeral: records are lost
// on restart and invisible to other instances.
package memory

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
)

var _ ceremony.Store = (*Store)(nil)

type key struct {
	tenant principal.TenantID
	kind   ceremony.Kind
	handle string
}

type entry struct {
	row ceremony.Row
	seq uint64
}

type bucketKey struct {
	tenant principal.TenantID
	kind   ceremony.Kind
}

type scopeKey struct {
	bucketKey
	scope string
}

// Store is safe for concurrent use. Like the SQL stores, it keeps instants to the microsecond.
type Store struct {
	clk      clock.Clock
	mu       sync.Mutex
	seq      uint64
	rows     map[key]*entry
	buckets  map[bucketKey]map[key]*entry
	scopes   map[scopeKey]int
	consumed map[key]time.Time
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{
		clk:      c,
		rows:     map[key]*entry{},
		buckets:  map[bucketKey]map[key]*entry{},
		scopes:   map[scopeKey]int{},
		consumed: map[key]time.Time{},
	}
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.rows {
		if k.tenant == t {
			s.remove(k)
		}
	}
	for k := range s.consumed {
		if k.tenant == t {
			delete(s.consumed, k)
		}
	}
	return nil
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, e := range s.rows {
		if !e.row.ExpiresAt.After(now) {
			s.remove(k)
			n++
		}
	}
	for k, until := range s.consumed {
		if !until.After(now) {
			delete(s.consumed, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) Put(ctx context.Context, r ceremony.Record) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.Validate(); err != nil {
		return 0, err
	}
	now := s.clk.Now()
	k := key{r.Tenant(), r.Kind(), string(r.HandleHash())}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.rows[k]; ok && old.row.ExpiresAt.After(now) {
		return 0, store.ErrConflict
	}
	s.remove(k)
	s.seq++
	s.insert(k, &entry{seq: s.seq, row: ceremony.Row{
		Tenant:     r.Tenant(),
		Kind:       r.Kind(),
		HandleHash: r.HandleHash(),
		ScopeHash:  r.ScopeHash(),
		Pending:    principal.SealedFromBytes(r.Pending.Bytes()),
		Payload:    r.Payload(),
		Attempts:   r.Attempts(),
		ExpiresAt:  r.ExpiresAt().Truncate(time.Microsecond),
		CreatedAt:  r.CreatedAt().Truncate(time.Microsecond),
	}})
	scope := string(r.ScopeHash())
	evicted := 0
	if s.scopes[scopeKey{bucketKey{k.tenant, k.kind}, scope}] > r.Kind().MaxLivePerScope() {
		evicted += s.evict(k, now, func(e *entry) bool { return string(e.row.ScopeHash) == scope }, r.Kind().MaxLivePerScope())
	}
	if ceiling := r.Kind().MaxLivePerTenant(); ceiling > 0 && len(s.buckets[bucketKey{k.tenant, k.kind}]) > ceiling {
		evicted += s.evict(k, now, func(*entry) bool { return true }, ceiling)
	}
	return evicted, nil
}

func (s *Store) insert(k key, e *entry) {
	s.rows[k] = e
	bk := bucketKey{k.tenant, k.kind}
	if s.buckets[bk] == nil {
		s.buckets[bk] = map[key]*entry{}
	}
	s.buckets[bk][k] = e
	s.scopes[scopeKey{bk, string(e.row.ScopeHash)}]++
}

func (s *Store) remove(k key) {
	e, ok := s.rows[k]
	if !ok {
		return
	}
	delete(s.rows, k)
	bk := bucketKey{k.tenant, k.kind}
	delete(s.buckets[bk], k)
	if len(s.buckets[bk]) == 0 {
		delete(s.buckets, bk)
	}
	sk := scopeKey{bk, string(e.row.ScopeHash)}
	if s.scopes[sk]--; s.scopes[sk] <= 0 {
		delete(s.scopes, sk)
	}
}

func (s *Store) evict(keep key, now time.Time, same func(*entry) bool, limit int) int {
	if limit <= 0 {
		return 0
	}
	type cand struct {
		k key
		e *entry
	}
	var others []cand
	for k, e := range s.buckets[bucketKey{keep.tenant, keep.kind}] {
		if k == keep || !e.row.ExpiresAt.After(now) || !same(e) {
			continue
		}
		others = append(others, cand{k, e})
	}
	if len(others) < limit {
		return 0
	}
	slices.SortFunc(others, func(a, b cand) int {
		if c := b.e.row.CreatedAt.Compare(a.e.row.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(b.e.seq, a.e.seq)
	})
	victims := others[limit-1:]
	for _, v := range victims {
		s.remove(v.k)
	}
	return len(victims)
}

func lookupKey(t principal.TenantID, k ceremony.Kind, handle []byte) (key, error) {
	if len(handle) < ceremony.HandleHashLen {
		return key{}, ceremony.ErrHandleTooShort
	}
	return key{t, k, string(handle)}, nil
}

func (s *Store) live(k key, now time.Time) (*entry, bool) {
	e, ok := s.rows[k]
	if !ok || !e.row.ExpiresAt.After(now) {
		return nil, false
	}
	return e, true
}

func (s *Store) Peek(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (ceremony.Record, error) {
	if err := ctx.Err(); err != nil {
		return ceremony.Record{}, err
	}
	kk, err := lookupKey(t, k, handleHash)
	if err != nil {
		return ceremony.Record{}, err
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(kk, now)
	if !ok {
		return ceremony.Record{}, store.ErrNotFound
	}
	return ceremony.Restore(e.row)
}

func (s *Store) Consume(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (ceremony.Record, error) {
	if err := ctx.Err(); err != nil {
		return ceremony.Record{}, err
	}
	kk, err := lookupKey(t, k, handleHash)
	if err != nil {
		return ceremony.Record{}, err
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(kk, now)
	if !ok {
		return ceremony.Record{}, store.ErrNotFound
	}
	s.remove(kk)
	return ceremony.Restore(e.row)
}

func (s *Store) RecordFailure(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	kk, err := lookupKey(t, k, handleHash)
	if err != nil {
		return 0, err
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(kk, now)
	if !ok {
		return 0, store.ErrNotFound
	}
	remaining := k.MaxAttempts() - e.row.Attempts - 1
	if remaining <= 0 {
		s.remove(kk)
		return 0, nil
	}
	e.row.Attempts++
	return remaining, nil
}

func (s *Store) MarkConsumed(ctx context.Context, t principal.TenantID, k ceremony.Kind, handleHash []byte, until time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !k.Valid() {
		return false, errors.Join(ceremony.ErrInvalidRecord, errors.New("invalid kind"))
	}
	if !k.Stateless() {
		return false, ceremony.ErrStoredKind
	}
	kk, err := lookupKey(t, k, handleHash)
	if err != nil {
		return false, err
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.consumed[kk]; ok && prev.After(now) {
		return false, nil
	}
	s.consumed[kk] = until.Truncate(time.Microsecond)
	return true, nil
}

func (s *Store) DeleteForScope(ctx context.Context, t principal.TenantID, scopeHash []byte, kinds ...ceremony.Kind) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(scopeHash) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, e := range s.rows {
		if k.tenant != t || string(e.row.ScopeHash) != string(scopeHash) {
			continue
		}
		if len(kinds) > 0 && !slices.Contains(kinds, k.kind) {
			continue
		}
		s.remove(k)
		n++
	}
	return n, nil
}
