// Package memory provides an in-process tokens.Store. It reports store.Ephemeral: families and keys
// are lost on restart and invisible to other instances.
package memory

import (
	"bytes"
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
	"github.com/JLugagne/egauth/store/tokens"
)

var _ tokens.Store = (*Store)(nil)

type familyKey struct {
	tenant principal.TenantID
	family uuid.UUID
}

type keyRef struct {
	tenant principal.TenantID
	hash   string
}

type refresh struct {
	row        tokens.RefreshRow
	consumedAt time.Time
	consumedBy []byte
	revoked    bool
}

type revocation struct {
	seq     uint64
	rev     tokens.Revocation
	expires time.Time
}

// Store is safe for concurrent use. Every decision reads the store clock, never an instant carried
// by a request, and instants are kept to the microsecond like the SQL stores. A rotation whose Next
// ends after the presented token's family is refused with store.ErrConflict.
type Store struct {
	clk      clock.Clock
	mu       sync.Mutex
	tokens   map[string]*refresh
	families map[familyKey][]string
	feed     []revocation
	seq      uint64
	keys     map[keyRef]*tokens.APIKey
	keyIDs   map[uuid.UUID]keyRef
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{
		clk:      c,
		tokens:   map[string]*refresh{},
		families: map[familyKey][]string{},
		keys:     map[keyRef]*tokens.APIKey{},
		keyIDs:   map[uuid.UUID]keyRef{},
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
	for fk := range s.families {
		if fk.tenant == t {
			s.revoke(fk, now)
			s.dropFamily(fk)
		}
	}
	for ref, k := range s.keys {
		if ref.tenant == t {
			s.dropKey(ref, k.ID)
		}
	}
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
	for h, r := range s.tokens {
		if !now.Before(r.row.IdleExpiresAt) || !now.Before(r.row.FamilyExpiresAt) {
			s.dropToken(h)
			n++
		}
	}
	for ref, k := range s.keys {
		if !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt) {
			s.dropKey(ref, k.ID)
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

func (s *Store) dropToken(h string) {
	r, ok := s.tokens[h]
	if !ok {
		return
	}
	delete(s.tokens, h)
	fk := familyKey{r.row.Subject.Tenant, r.row.Family}
	s.families[fk] = slices.DeleteFunc(s.families[fk], func(x string) bool { return x == h })
	if len(s.families[fk]) == 0 {
		delete(s.families, fk)
	}
}

func (s *Store) dropFamily(fk familyKey) {
	for _, h := range slices.Clone(s.families[fk]) {
		s.dropToken(h)
	}
}

func (s *Store) dropKey(ref keyRef, id uuid.UUID) {
	delete(s.keys, ref)
	delete(s.keyIDs, id)
}

func (s *Store) revoke(fk familyKey, now time.Time) {
	var expires time.Time
	appended := false
	for _, h := range s.families[fk] {
		r := s.tokens[h]
		expires = maxTime(expires, r.row.FamilyExpiresAt)
		if !r.revoked {
			r.revoked = true
			appended = true
		}
	}
	if !appended {
		return
	}
	s.seq++
	s.feed = append(s.feed, revocation{
		seq:     s.seq,
		rev:     tokens.Revocation{Tenant: fk.tenant, Family: fk.family, At: now},
		expires: expires,
	})
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func rowOf(r tokens.RefreshRecord) tokens.RefreshRow {
	return tokens.RefreshRow{
		TokenHash:         r.TokenHash(),
		Family:            r.Family(),
		Subject:           r.Subject(),
		Lineage:           r.Lineage(),
		Sealed:            r.Sealed(),
		AppClaims:         nonEmpty(r.AppClaims()),
		SecurityEpoch:     r.Epoch(),
		ClientFingerprint: nonEmpty(r.ClientFingerprint()),
		IdleExpiresAt:     r.IdleExpiresAt().UTC().Truncate(time.Microsecond),
		FamilyExpiresAt:   r.FamilyExpiresAt().UTC().Truncate(time.Microsecond),
		CreatedAt:         r.CreatedAt().UTC().Truncate(time.Microsecond),
	}
}

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *Store) insert(r tokens.RefreshRecord) error {
	row := rowOf(r)
	if _, err := tokens.RestoreRefreshRecord(row); err != nil {
		return err
	}
	h := string(row.TokenHash)
	if _, ok := s.tokens[h]; ok {
		return store.ErrConflict
	}
	s.tokens[h] = &refresh{row: row}
	fk := familyKey{row.Subject.Tenant, row.Family}
	s.families[fk] = append(s.families[fk], h)
	return nil
}

func (s *Store) Create(ctx context.Context, r tokens.RefreshRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.IsZero() {
		return tokens.ErrInvalidRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.families[familyKey{r.Tenant(), r.Family()}]; ok {
		return store.ErrConflict
	}
	return s.insert(r)
}

func (s *Store) lookup(t principal.TenantID, tokenHash []byte) (*refresh, bool) {
	r, ok := s.tokens[string(tokenHash)]
	if !ok || r.row.Subject.Tenant != t {
		return nil, false
	}
	return r, true
}

func usable(r *refresh, now time.Time) error {
	switch {
	case r.revoked || !now.Before(r.row.FamilyExpiresAt):
		return tokens.ErrRevoked
	case !now.Before(r.row.IdleExpiresAt):
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (tokens.RefreshRecord, error) {
	if err := ctx.Err(); err != nil {
		return tokens.RefreshRecord{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lookup(t, tokenHash)
	if !ok {
		return tokens.RefreshRecord{}, store.ErrNotFound
	}
	if err := usable(r, now); err != nil {
		return tokens.RefreshRecord{}, err
	}
	return tokens.RestoreRefreshRecord(r.row)
}

func continues(r tokens.RefreshRow, next tokens.RefreshRecord) bool {
	return r.Subject == next.Subject() && r.Lineage == next.Lineage() && r.Family == next.Family()
}

func (s *Store) ConsumeForRotation(ctx context.Context, req tokens.RotationRequest) (tokens.Rotation, error) {
	if err := ctx.Err(); err != nil {
		return tokens.Rotation{}, err
	}
	if req.Next.IsZero() || len(req.Presented) != tokens.HashLen {
		return tokens.Rotation{}, errors.Join(tokens.ErrInvalidRecord, errors.New("a presented digest and a next record are required"))
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lookup(req.Next.Tenant(), req.Presented)
	if !ok {
		return tokens.Rotation{}, store.ErrNotFound
	}
	if err := usable(r, now); err != nil {
		return tokens.Rotation{}, err
	}
	if !continues(r.row, req.Next) {
		return tokens.Rotation{}, store.ErrConflict
	}
	if !r.consumedAt.IsZero() {
		fp := req.Next.ClientFingerprint()
		if now.Sub(r.consumedAt) < tokens.ReuseGrace && len(r.consumedBy) > 0 && bytes.Equal(r.consumedBy, fp) {
			return tokens.Rotation{}, tokens.ErrConcurrent
		}
		s.revoke(familyKey{r.row.Subject.Tenant, r.row.Family}, now)
		return tokens.Rotation{}, tokens.ErrReused
	}
	if req.Next.FamilyExpiresAt().UTC().Truncate(time.Microsecond).After(r.row.FamilyExpiresAt) {
		return tokens.Rotation{}, store.ErrConflict
	}
	if err := s.insert(req.Next); err != nil {
		return tokens.Rotation{}, err
	}
	r.consumedAt = now
	r.consumedBy = req.Next.ClientFingerprint()
	return tokens.Rotation{Family: r.row.Family, ConsumedAt: now}, nil
}

func (s *Store) familyRows(fk familyKey) []*refresh {
	out := make([]*refresh, 0, len(s.families[fk]))
	for _, h := range s.families[fk] {
		out = append(out, s.tokens[h])
	}
	return out
}

func (s *Store) Reissue(ctx context.Context, req tokens.ReissueRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Next.IsZero() {
		return tokens.ErrInvalidRecord
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	fk := familyKey{req.Next.Tenant(), req.Family}
	rows := s.familyRows(fk)
	if len(rows) == 0 || req.Next.Family() == req.Family {
		return store.ErrConflict
	}
	if _, taken := s.families[familyKey{req.Next.Tenant(), req.Next.Family()}]; taken {
		return store.ErrConflict
	}
	if _, taken := s.tokens[string(req.Next.TokenHash())]; taken {
		return store.ErrConflict
	}
	st := state(rows)
	if st.Revoked || !st.Live(now) || st.Subject != req.Next.Subject() || st.Lineage != req.Next.Lineage() {
		return store.ErrConflict
	}
	for _, r := range rows {
		if r.row.Subject != st.Subject || r.row.Lineage != st.Lineage {
			return store.ErrConflict
		}
	}
	if err := s.insert(req.Next); err != nil {
		return err
	}
	s.revoke(fk, now)
	return nil
}

func (s *Store) FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (tokens.FamilyState, error) {
	if err := ctx.Err(); err != nil {
		return tokens.FamilyState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := s.familyRows(familyKey{t, family})
	if len(rows) == 0 {
		return tokens.FamilyState{}, store.ErrNotFound
	}
	return state(rows), nil
}

func state(rows []*refresh) tokens.FamilyState {
	st := tokens.FamilyState{Subject: rows[0].row.Subject, Lineage: rows[0].row.Lineage}
	for _, r := range rows {
		st.Revoked = st.Revoked || r.revoked
		st.ExpiresAt = maxTime(st.ExpiresAt, r.row.FamilyExpiresAt)
	}
	return st
}

func (s *Store) RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoke(familyKey{t, family}, now)
	return nil
}

func (s *Store) subjectFamilies(sub principal.Subject, keep func(tokens.RefreshRow) bool) []familyKey {
	var out []familyKey
	for fk, hs := range s.families {
		if fk.tenant != sub.Tenant || len(hs) == 0 {
			continue
		}
		r := s.tokens[hs[0]].row
		if r.Subject == sub && !keep(r) {
			out = append(out, fk)
		}
	}
	slices.SortFunc(out, func(a, b familyKey) int { return cmp.Compare(a.family.String(), b.family.String()) })
	return out
}

func (s *Store) RevokeForSubject(ctx context.Context, sub principal.Subject, exceptLineage uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := func(r tokens.RefreshRow) bool { return exceptLineage != uuid.Nil && r.Lineage == exceptLineage }
	for _, fk := range s.subjectFamilies(sub, keep) {
		s.revoke(fk, now)
	}
	return nil
}

func (s *Store) RevocationsSince(ctx context.Context, c store.Cursor) ([]tokens.Revocation, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, c, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, _ := slices.BinarySearchFunc(s.feed, c.Position()+1, func(r revocation, pos uint64) int { return cmp.Compare(r.seq, pos) })
	out := make([]tokens.Revocation, 0, len(s.feed)-i)
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
	for _, fk := range s.subjectFamilies(sub, func(tokens.RefreshRow) bool { return false }) {
		s.revoke(fk, now)
		s.dropFamily(fk)
	}
	for ref, k := range s.keys {
		if k.Owner == sub {
			s.dropKey(ref, k.ID)
		}
	}
	return nil
}

func cloneKey(k tokens.APIKey) tokens.APIKey {
	k.KeyHash = slices.Clone(k.KeyHash)
	k.AppClaims = slices.Clone(k.AppClaims)
	k.CreatedAt = k.CreatedAt.UTC().Truncate(time.Microsecond)
	if !k.ExpiresAt.IsZero() {
		k.ExpiresAt = k.ExpiresAt.UTC().Truncate(time.Microsecond)
	}
	if !k.RevokedAt.IsZero() {
		k.RevokedAt = k.RevokedAt.UTC().Truncate(time.Microsecond)
	}
	return k
}

func (s *Store) CreateAPIKey(ctx context.Context, k tokens.APIKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := k.Validate(); err != nil {
		return err
	}
	ref := keyRef{k.Owner.Tenant, string(k.KeyHash)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[ref]; ok {
		return store.ErrConflict
	}
	if _, ok := s.keyIDs[k.ID]; ok {
		return store.ErrConflict
	}
	stored := cloneKey(k)
	s.keys[ref] = &stored
	s.keyIDs[k.ID] = ref
	return nil
}

func (s *Store) GetAPIKey(ctx context.Context, t principal.TenantID, keyHash []byte) (tokens.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return tokens.APIKey{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyRef{t, string(keyHash)}]
	if !ok || (!k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt)) {
		return tokens.APIKey{}, store.ErrNotFound
	}
	return cloneKey(*k), nil
}

func (s *Store) ListAPIKeys(ctx context.Context, owner principal.Subject) ([]tokens.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []tokens.APIKey{}
	for _, k := range s.keys {
		if k.Owner == owner {
			out = append(out, cloneKey(*k))
		}
	}
	slices.SortFunc(out, func(a, b tokens.APIKey) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.ID.String(), b.ID.String())
	})
	return out, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, owner principal.Subject, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.keyIDs[id]
	if !ok || s.keys[ref].Owner != owner {
		return store.ErrNotFound
	}
	if k := s.keys[ref]; k.RevokedAt.IsZero() {
		k.RevokedAt = now
	}
	return nil
}
