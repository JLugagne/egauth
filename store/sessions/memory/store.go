// Package memory provides an in-process sessions.Store. It reports store.Ephemeral: sessions are lost
// on restart and invisible to other instances.
package memory

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/sessions"
)

var _ sessions.Store = (*Store)(nil)

type revocation struct {
	seq     uint64
	rev     sessions.Revocation
	expires time.Time
}

// Store is safe for concurrent use. Every decision reads the store clock, and instants are kept to
// the microsecond like the SQL stores. Rotate refuses a Next that ends after the row's absolute
// expiry.
type Store struct {
	clk    clock.Clock
	mu     sync.Mutex
	rows   map[uuid.UUID]*sessions.Row
	byHash map[string]uuid.UUID
	feed   []revocation
	seq    uint64
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{clk: c, rows: map[uuid.UUID]*sessions.Row{}, byHash: map[string]uuid.UUID{}}
}

func (s *Store) now() time.Time { return s.clk.Now().UTC().Truncate(time.Microsecond) }

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func live(r *sessions.Row, now time.Time) bool {
	return now.Before(r.IdleExpiresAt) && now.Before(r.AbsoluteExpiresAt)
}

func (s *Store) end(id uuid.UUID, now time.Time) {
	r, ok := s.rows[id]
	if !ok {
		return
	}
	delete(s.rows, id)
	delete(s.byHash, string(r.TokenHash))
	s.seq++
	s.feed = append(s.feed, revocation{
		seq:     s.seq,
		rev:     sessions.Revocation{Tenant: r.Subject.Tenant, Session: id, At: now},
		expires: r.AbsoluteExpiresAt,
	})
}

func (s *Store) endWhere(now time.Time, match func(*sessions.Row) bool) {
	var victims []uuid.UUID
	for id, r := range s.rows {
		if match(r) {
			victims = append(victims, id)
		}
	}
	slices.SortFunc(victims, func(a, b uuid.UUID) int { return cmp.Compare(a.String(), b.String()) })
	for _, id := range victims {
		s.end(id, now)
	}
}

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endWhere(now, func(r *sessions.Row) bool { return r.Subject.Tenant == t })
	return nil
}

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, r := range s.rows {
		if !live(r, now) {
			delete(s.rows, id)
			delete(s.byHash, string(r.TokenHash))
			n++
		}
	}
	kept := s.feed[:0]
	for _, r := range s.feed {
		if now.Before(r.expires) {
			kept = append(kept, r)
			continue
		}
		n++
	}
	s.feed = kept
	return n, nil
}

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func rowOf(r sessions.Record) sessions.Row {
	return sessions.Row{
		ID:                r.ID(),
		TokenHash:         r.TokenHash(),
		Subject:           r.Subject(),
		Lineage:           r.Lineage(),
		Sealed:            r.Sealed(),
		AppClaims:         nonEmpty(r.AppClaims()),
		SecurityEpoch:     r.Epoch(),
		ClientFingerprint: nonEmpty(r.ClientFingerprint()),
		IdleExpiresAt:     r.IdleExpiresAt().UTC().Truncate(time.Microsecond),
		AbsoluteExpiresAt: r.AbsoluteExpiresAt().UTC().Truncate(time.Microsecond),
		CheckedAt:         r.CheckedAt().UTC().Truncate(time.Microsecond),
		CreatedAt:         r.CreatedAt().UTC().Truncate(time.Microsecond),
	}
}

func (s *Store) Create(ctx context.Context, r sessions.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.IsZero() {
		return sessions.ErrInvalidRecord
	}
	row := rowOf(r)
	if _, err := sessions.Restore(row); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[row.ID]; ok {
		return store.ErrConflict
	}
	if _, ok := s.byHash[string(row.TokenHash)]; ok {
		return store.ErrConflict
	}
	s.rows[row.ID] = &row
	s.byHash[string(row.TokenHash)] = row.ID
	return nil
}

func (s *Store) lookup(t principal.TenantID, tokenHash []byte, now time.Time) (*sessions.Row, bool) {
	id, ok := s.byHash[string(tokenHash)]
	if !ok {
		return nil, false
	}
	r := s.rows[id]
	if r.Subject.Tenant != t || !live(r, now) {
		return nil, false
	}
	return r, true
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (sessions.Record, error) {
	if err := ctx.Err(); err != nil {
		return sessions.Record{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lookup(t, tokenHash, now)
	if !ok {
		return sessions.Record{}, store.ErrNotFound
	}
	return sessions.Restore(*r)
}

func (s *Store) Touch(ctx context.Context, t principal.TenantID, tokenHash []byte, idleUntil time.Time) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lookup(t, tokenHash, now)
	if !ok {
		return time.Time{}, store.ErrNotFound
	}
	until := idleUntil.UTC().Truncate(time.Microsecond)
	if until.After(r.AbsoluteExpiresAt) {
		until = r.AbsoluteExpiresAt
	}
	if until.After(r.IdleExpiresAt) {
		r.IdleExpiresAt = until
	}
	return r.IdleExpiresAt, nil
}

func sameSession(r *sessions.Row, next sessions.Record) bool {
	return r.Subject == next.Subject() && r.Lineage == next.Lineage()
}

func (s *Store) Rotate(ctx context.Context, req sessions.RotateRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Next.IsZero() {
		return sessions.ErrInvalidRecord
	}
	row := rowOf(req.Next)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lookup(req.Next.Tenant(), req.Previous, now)
	if !ok || r.ID != row.ID || !sameSession(r, req.Next) || row.AbsoluteExpiresAt.After(r.AbsoluteExpiresAt) {
		return store.ErrConflict
	}
	if owner, taken := s.byHash[string(row.TokenHash)]; taken && owner != r.ID {
		return store.ErrConflict
	}
	row.CreatedAt = r.CreatedAt
	if _, err := sessions.Restore(row); err != nil {
		return err
	}
	delete(s.byHash, string(r.TokenHash))
	*r = row
	s.byHash[string(row.TokenHash)] = row.ID
	return nil
}

func (s *Store) Replace(ctx context.Context, req sessions.ReplaceRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Next.IsZero() {
		return errors.Join(sessions.ErrInvalidRecord, errors.New("a next record is required"))
	}
	row := rowOf(req.Next)
	if _, err := sessions.Restore(row); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[req.Previous]
	if !ok || !live(r, now) || row.ID == req.Previous || !sameSession(r, req.Next) {
		return store.ErrConflict
	}
	if _, taken := s.rows[row.ID]; taken {
		return store.ErrConflict
	}
	if _, taken := s.byHash[string(row.TokenHash)]; taken {
		return store.ErrConflict
	}
	s.end(req.Previous, now)
	s.rows[row.ID] = &row
	s.byHash[string(row.TokenHash)] = row.ID
	return nil
}

func (s *Store) Revoke(ctx context.Context, t principal.TenantID, tokenHash []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byHash[string(tokenHash)]; ok && s.rows[id].Subject.Tenant == t {
		s.end(id, now)
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, sub principal.Subject, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok && r.Subject == sub {
		s.end(id, now)
	}
	return nil
}

func (s *Store) RevokeForSubject(ctx context.Context, sub principal.Subject, exceptLineage uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endWhere(now, func(r *sessions.Row) bool {
		return r.Subject == sub && (exceptLineage == uuid.Nil || r.Lineage != exceptLineage)
	})
	return nil
}

func (s *Store) RevocationsSince(ctx context.Context, c store.Cursor) ([]sessions.Revocation, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, c, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, _ := slices.BinarySearchFunc(s.feed, c.Position()+1, func(r revocation, pos uint64) int { return cmp.Compare(r.seq, pos) })
	out := make([]sessions.Revocation, 0, len(s.feed)-i)
	last := c
	for _, r := range s.feed[i:] {
		out = append(out, r.rev)
		last = store.RestoreCursor(r.seq)
	}
	return out, last, nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endWhere(now, func(r *sessions.Row) bool { return r.Subject == sub })
	return nil
}
