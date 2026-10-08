// Package memory provides an in-process keys.Store. It reports store.Ephemeral: keys, tombstones and
// the change feed are lost on restart and invisible to other instances.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

var _ keys.Store = (*Store)(nil)

const feedRetention = 24 * time.Hour

type row struct {
	key keys.Key
	seq uint64
}

type change struct {
	seq    uint64
	tenant principal.TenantID
	at     time.Time
}

// Store is safe for concurrent use. Expiry, reaping and feed pruning read the store clock; the
// CreatedAt, NotAfter, RetiredAt and OverlapUntil a caller gives are stored as given, a zero CreatedAt
// becoming the store time. Instants are kept to the microsecond like the SQL stores. Feed positions
// are handed out under the store lock, so they follow commit order.
//
// ReapExpired prunes feed entries older than a day. ChangesSince with a non-zero cursor older than
// the pruned entries returns an error wrapping store.ErrNotFound instead of a feed with a silent gap:
// the poller must drop its key caches and resume from the zero cursor.
type Store struct {
	clk        clock.Clock
	mu         sync.Mutex
	rows       map[principal.TenantID][]*row
	tombstones map[principal.TenantID]struct{}
	feed       []change
	pruned     uint64
	seq        uint64
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{
		clk:        c,
		rows:       map[principal.TenantID][]*row{},
		tombstones: map[principal.TenantID]struct{}{},
	}
}

func (s *Store) now() time.Time { return s.clk.Now().UTC().Truncate(time.Microsecond) }

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

var (
	errInvalidKey   = errors.New("keys: invalid key")
	errInvalidLimit = errors.New("keys: limit must be positive")
	errInvalidSeal  = errors.New("keys: invalid reseal")
	errNotSigner    = errors.New("keys: previous key is not the tenant's active signer")
	errKeyIDTaken   = errors.New("keys: key id exists in the tenant")
	errOutranked    = errors.New("keys: next key would not become the tenant's active signer")
	errFeedGap      = errors.New("keys: cursor is older than the retained change feed; drop the key caches and resume from the zero cursor")
)

func micro(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Microsecond)
}

func cloneKey(k keys.Key) keys.Key {
	k.Sealed = bytes.Clone(k.Sealed)
	k.CreatedAt = micro(k.CreatedAt)
	k.NotAfter = micro(k.NotAfter)
	if k.RetiredAt != nil {
		r := micro(*k.RetiredAt)
		k.RetiredAt = &r
	}
	return k
}

func (s *Store) checkKey(k keys.Key) (keys.Key, error) {
	if k.AADVersion != keys.AADVersionCurrent {
		return keys.Key{}, keys.ErrLegacyAADVersion
	}
	if k.KeyID == "" || k.Alg == "" || len(k.Sealed) == 0 {
		return keys.Key{}, errInvalidKey
	}
	k = cloneKey(k)
	if k.CreatedAt.IsZero() {
		k.CreatedAt = s.now()
	}
	return k, nil
}

func (s *Store) record(t principal.TenantID, now time.Time) {
	s.seq++
	s.feed = append(s.feed, change{seq: s.seq, tenant: t, at: now})
}

func (s *Store) find(t principal.TenantID, id string) *row {
	for _, r := range s.rows[t] {
		if r.key.KeyID == id {
			return r
		}
	}
	return nil
}

func (s *Store) insert(k keys.Key) {
	s.seq++
	s.rows[k.Tenant] = append(s.rows[k.Tenant], &row{key: k, seq: s.seq})
}

func (s *Store) CreateTenant(ctx context.Context, initial keys.Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k, err := s.checkKey(initial)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dead := s.tombstones[k.Tenant]; dead {
		return keys.ErrTenantTombstoned
	}
	if len(s.rows[k.Tenant]) > 0 {
		return store.ErrConflict
	}
	s.insert(k)
	s.record(k.Tenant, s.now())
	return nil
}

func (s *Store) TenantExists(ctx context.Context, t principal.TenantID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows[t]) > 0, nil
}

func (s *Store) PutKey(ctx context.Context, key keys.Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k, err := s.checkKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dead := s.tombstones[k.Tenant]; dead {
		return keys.ErrTenantTombstoned
	}
	if s.find(k.Tenant, k.KeyID) != nil {
		return store.ErrConflict
	}
	s.insert(k)
	s.record(k.Tenant, s.now())
	return nil
}

func newest(a, b keys.Key) int {
	return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.KeyID, a.KeyID))
}

func (s *Store) ActiveKey(ctx context.Context, t principal.TenantID) (keys.Key, error) {
	if err := ctx.Err(); err != nil {
		return keys.Key{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	best := s.signer(t, now)
	if best == nil {
		return keys.Key{}, keys.ErrNoActiveKey
	}
	return cloneKey(best.key), nil
}

func (s *Store) VerificationKeys(ctx context.Context, t principal.TenantID) ([]keys.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []keys.Key{}
	for _, r := range s.rows[t] {
		if r.key.Verifies(now) {
			out = append(out, cloneKey(r.key))
		}
	}
	slices.SortFunc(out, newest)
	return out, nil
}

func (s *Store) Rotate(ctx context.Context, r keys.Rotation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.Valid() {
		return keys.ErrInvalidRotation
	}
	next, err := s.checkKey(r.Next)
	if err != nil {
		return errors.Join(keys.ErrInvalidRotation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dead := s.tombstones[next.Tenant]; dead {
		return keys.ErrTenantTombstoned
	}
	now := s.now()
	signer := s.signer(next.Tenant, now)
	if signer == nil || signer.key.KeyID != r.Previous {
		return errors.Join(store.ErrConflict, errNotSigner)
	}
	if s.find(next.Tenant, next.KeyID) != nil {
		return errors.Join(store.ErrConflict, errKeyIDTaken)
	}
	if !s.becomesSigner(next, signer, now) {
		return errors.Join(store.ErrConflict, errOutranked)
	}
	prev := signer
	retired := micro(r.RetiredAt)
	until := micro(r.OverlapUntil)
	prev.key.RetiredAt = &retired
	if prev.key.NotAfter.IsZero() || prev.key.NotAfter.After(until) {
		prev.key.NotAfter = until
	}
	s.insert(next)
	s.record(next.Tenant, now)
	return nil
}

func (s *Store) signer(t principal.TenantID, now time.Time) *row {
	var best *row
	for _, r := range s.rows[t] {
		if r.key.IsActive(now) && (best == nil || newest(r.key, best.key) < 0) {
			best = r
		}
	}
	return best
}

func (s *Store) becomesSigner(next keys.Key, prev *row, now time.Time) bool {
	if !next.IsActive(now) {
		return false
	}
	for _, r := range s.rows[next.Tenant] {
		if r != prev && r.key.IsActive(now) && newest(next, r.key) > 0 {
			return false
		}
	}
	return true
}

func (s *Store) wipe(t principal.TenantID) bool {
	had := len(s.rows[t]) > 0
	delete(s.rows, t)
	return had
}

func (s *Store) RevokeTenantKeys(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wipe(t) {
		s.record(t, s.now())
	}
	return nil
}

func (s *Store) Tombstone(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.wipe(t)
	if _, dead := s.tombstones[t]; !dead {
		s.tombstones[t] = struct{}{}
		changed = true
	}
	if changed {
		s.record(t, s.now())
	}
	return nil
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	return s.Tombstone(ctx, t)
}

func (s *Store) IsTombstoned(ctx context.Context, t principal.TenantID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, dead := s.tombstones[t]
	return dead, nil
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	tenants := make([]principal.TenantID, 0, len(s.rows))
	for t := range s.rows {
		tenants = append(tenants, t)
	}
	slices.SortFunc(tenants, func(a, b principal.TenantID) int { return cmp.Compare(a.String(), b.String()) })
	for _, t := range tenants {
		kept := s.rows[t][:0]
		var removed int64
		for _, r := range s.rows[t] {
			if !r.key.Verifies(now) {
				removed++
				continue
			}
			kept = append(kept, r)
		}
		if removed == 0 {
			continue
		}
		n += removed
		if len(kept) == 0 {
			delete(s.rows, t)
		} else {
			s.rows[t] = kept
		}
		s.record(t, now)
	}
	feed := s.feed[:0]
	for _, c := range s.feed {
		if now.Sub(c.at) < feedRetention {
			feed = append(feed, c)
			continue
		}
		s.pruned = max(s.pruned, c.seq)
	}
	s.feed = feed
	return n, nil
}

func (s *Store) ChangesSince(ctx context.Context, c store.Cursor) ([]keys.Change, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, c, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !c.IsZero() && c.Position() < s.pruned {
		return nil, c, errors.Join(store.ErrNotFound, errFeedGap)
	}
	out := []keys.Change{}
	seen := map[principal.TenantID]struct{}{}
	last := c
	for _, ch := range s.feed {
		if ch.seq <= c.Position() {
			continue
		}
		last = store.RestoreCursor(ch.seq)
		if _, dup := seen[ch.tenant]; dup {
			continue
		}
		seen[ch.tenant] = struct{}{}
		out = append(out, keys.Change{Tenant: ch.tenant})
	}
	return out, last, nil
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, rows := range s.rows {
		for _, r := range rows {
			if r.key.AADVersion == keys.AADVersionLegacy {
				n++
			}
		}
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]keys.V016Row, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, after, err
	}
	if limit < 1 {
		return nil, after, errInvalidLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []*row
	for _, rows := range s.rows {
		for _, r := range rows {
			if r.key.AADVersion == keys.AADVersionLegacy && r.seq > after.Position() {
				found = append(found, r)
			}
		}
	}
	slices.SortFunc(found, func(a, b *row) int { return cmp.Compare(a.seq, b.seq) })
	if len(found) > limit {
		found = found[:limit]
	}
	out := make([]keys.V016Row, 0, len(found))
	cur := after
	for _, r := range found {
		out = append(out, keys.V016Row{
			Ref:    keys.SealedRef{Tenant: r.key.Tenant, KeyID: r.key.KeyID},
			Sealed: bytes.Clone(r.key.Sealed),
		})
		cur = store.RestoreCursor(r.seq)
	}
	return out, cur, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r keys.Reseal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(r.Old) == 0 || len(r.New) == 0 || r.Ref.KeyID == "" {
		return false, errInvalidSeal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := s.find(r.Ref.Tenant, r.Ref.KeyID)
	if found == nil || !bytes.Equal(found.key.Sealed, r.Old) {
		return false, nil
	}
	found.key.Sealed = bytes.Clone(r.New)
	found.key.AADVersion = keys.AADVersionCurrent
	return true, nil
}

func (s *Store) addV016(k keys.Key) {
	k = cloneKey(k)
	k.AADVersion = keys.AADVersionLegacy
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = s.now()
	}
	s.insert(k)
}
