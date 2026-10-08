// Package memory provides an in-process mfa.Store. It reports store.Ephemeral: enrollments, recovery
// codes and lockout counters are lost on restart and invisible to other instances.
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
	"github.com/JLugagne/egauth/store/mfa"
)

var _ mfa.Store = (*Store)(nil)

type totpRow struct {
	mfa.Enrollment
	seq uint64
}

type recoveryCode struct {
	used bool
}

type counter struct {
	failed int
	last   time.Time
}

// Store is safe for concurrent use. Instants are kept to the microsecond like the SQL stores.
type Store struct {
	clk      clock.Clock
	mu       sync.Mutex
	totp     map[principal.Subject]*totpRow
	codes    map[principal.Subject]map[string]*recoveryCode
	recovery map[principal.Subject]*counter
	seq      uint64
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{
		clk:      c,
		totp:     map[principal.Subject]*totpRow{},
		codes:    map[principal.Subject]map[string]*recoveryCode{},
		recovery: map[principal.Subject]*counter{},
	}
}

func (s *Store) now() time.Time { return s.clk.Now().UTC().Truncate(time.Microsecond) }

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, t principal.TenantID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub := range s.totp {
		if sub.Tenant == t {
			delete(s.totp, sub)
		}
	}
	for sub := range s.codes {
		if sub.Tenant == t {
			delete(s.codes, sub)
		}
	}
	for sub := range s.recovery {
		if sub.Tenant == t {
			delete(s.recovery, sub)
		}
	}
	return nil
}

var (
	errInvalidSubject    = errors.New("mfa: invalid subject")
	errInvalidEnrollment = errors.New("mfa: invalid enrollment")
	errInvalidLockout    = errors.New("mfa: invalid lockout")
	errInvalidCodeHashes = errors.New("mfa: invalid recovery code hashes")
	errInvalidReseal     = errors.New("mfa: invalid reseal")
)

func checkEnrollment(e mfa.Enrollment) error {
	if e.Subject.IsZero() {
		return errInvalidSubject
	}
	if e.AADVersion != mfa.AADVersionCurrent {
		return mfa.ErrLegacyAADVersion
	}
	if len(e.Sealed) == 0 || e.FailedAttempts < 0 {
		return errInvalidEnrollment
	}
	return nil
}

func checkHashes(hashes []string) error {
	seen := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		if h == "" {
			return errInvalidCodeHashes
		}
		if _, dup := seen[h]; dup {
			return errInvalidCodeHashes
		}
		seen[h] = struct{}{}
	}
	return nil
}

func checkLockout(l mfa.Lockout) error {
	if l.Subject.IsZero() {
		return errInvalidSubject
	}
	if l.Max < 1 || l.Duration < 0 || l.Now.IsZero() {
		return errInvalidLockout
	}
	return nil
}

func clonePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

func (s *Store) put(e mfa.Enrollment) {
	row, ok := s.totp[e.Subject]
	if !ok {
		s.seq++
		row = &totpRow{seq: s.seq}
		s.totp[e.Subject] = row
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = s.now()
	}
	e.Sealed = bytes.Clone(e.Sealed)
	e.ConfirmedAt = clonePtr(e.ConfirmedAt)
	e.CreatedAt = e.CreatedAt.UTC().Truncate(time.Microsecond)
	if !e.LastAttemptAt.IsZero() {
		e.LastAttemptAt = e.LastAttemptAt.UTC().Truncate(time.Microsecond)
	}
	row.Enrollment = e
}

func (r *totpRow) out() mfa.Enrollment {
	e := r.Enrollment
	e.Sealed = bytes.Clone(e.Sealed)
	e.ConfirmedAt = clonePtr(e.ConfirmedAt)
	return e
}

func (s *Store) SaveTOTP(ctx context.Context, e mfa.Enrollment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkEnrollment(e); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put(e)
	return nil
}

func (s *Store) GetTOTP(ctx context.Context, sub principal.Subject) (mfa.Enrollment, error) {
	if err := ctx.Err(); err != nil {
		return mfa.Enrollment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.totp[sub]
	if !ok {
		return mfa.Enrollment{}, store.ErrNotFound
	}
	return r.out(), nil
}

func (s *Store) DeleteTOTP(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totp, sub)
	return nil
}

func (s *Store) HasConfirmedTOTP(ctx context.Context, sub principal.Subject) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.totp[sub]
	return ok && r.Confirmed(), nil
}

func (s *Store) enrolled() map[principal.Subject]struct{} {
	out := make(map[principal.Subject]struct{}, len(s.totp))
	for sub := range s.totp {
		out[sub] = struct{}{}
	}
	for sub, set := range s.codes {
		for _, c := range set {
			if !c.used {
				out[sub] = struct{}{}
				break
			}
		}
	}
	return out
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
	return int64(len(s.enrolled())), nil
}

func (s *Store) MarkTOTPUsed(ctx context.Context, sub principal.Subject, step int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.totp[sub]
	if !ok || step <= r.LastUsedStep {
		return false, nil
	}
	r.LastUsedStep = step
	r.FailedAttempts = 0
	r.LastAttemptAt = time.Time{}
	return true, nil
}

func bump(c counter, l mfa.Lockout) (counter, int) {
	now := l.Now.UTC().Truncate(time.Microsecond)
	if c.failed < l.Max {
		n := counter{failed: c.failed + 1, last: now}
		return n, n.failed
	}
	if l.Duration > 0 && !c.last.IsZero() && now.Sub(c.last) > l.Duration {
		return counter{failed: 1, last: now}, 1
	}
	return c, l.Max + 1
}

func (s *Store) IncrementTOTPAttempts(ctx context.Context, l mfa.Lockout) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := checkLockout(l); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.totp[l.Subject]
	if !ok {
		return 0, store.ErrNotFound
	}
	next, n := bump(counter{failed: r.FailedAttempts, last: r.LastAttemptAt}, l)
	r.FailedAttempts, r.LastAttemptAt = next.failed, next.last
	return n, nil
}

func (s *Store) ResetTOTPAttempts(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.totp[sub]; ok {
		r.FailedAttempts = 0
		r.LastAttemptAt = time.Time{}
	}
	return nil
}

func (s *Store) replaceCodes(sub principal.Subject, hashes []string) {
	delete(s.recovery, sub)
	delete(s.codes, sub)
	if len(hashes) == 0 {
		return
	}
	set := make(map[string]*recoveryCode, len(hashes))
	for _, h := range hashes {
		set[h] = &recoveryCode{}
	}
	s.codes[sub] = set
}

func (s *Store) ConfirmEnrollment(ctx context.Context, e mfa.Enrollment, codeHashes []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkEnrollment(e); err != nil {
		return err
	}
	if e.ConfirmedAt == nil {
		return errInvalidEnrollment
	}
	if err := checkHashes(codeHashes); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put(e)
	s.replaceCodes(e.Subject, codeHashes)
	return nil
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, sub principal.Subject, codeHashes []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sub.IsZero() {
		return errInvalidSubject
	}
	if err := checkHashes(codeHashes); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceCodes(sub, codeHashes)
	return nil
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, sub principal.Subject, codeHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[sub][codeHash]
	if !ok || c.used {
		return store.ErrNotFound
	}
	c.used = true
	if r, ok := s.totp[sub]; ok {
		r.FailedAttempts = 0
		r.LastAttemptAt = time.Time{}
	}
	delete(s.recovery, sub)
	return nil
}

func (s *Store) DeleteRecoveryCodes(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceCodes(sub, nil)
	return nil
}

func (s *Store) IncrementRecoveryAttempts(ctx context.Context, l mfa.Lockout) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := checkLockout(l); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur counter
	if c, ok := s.recovery[l.Subject]; ok {
		cur = *c
	}
	next, n := bump(cur, l)
	s.recovery[l.Subject] = &next
	return n, nil
}

func (s *Store) ResetRecoveryAttempts(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recovery, sub)
	return nil
}

func (s *Store) DeleteForSubject(ctx context.Context, sub principal.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totp, sub)
	delete(s.codes, sub)
	delete(s.recovery, sub)
	return nil
}

func (s *Store) CountLegacySealed(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, r := range s.totp {
		if r.AADVersion == mfa.AADVersionLegacy {
			n++
		}
	}
	return n, nil
}

func (s *Store) V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]mfa.V016Row, store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, after, err
	}
	if limit < 1 {
		return nil, after, errors.New("mfa: limit must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []*totpRow
	for _, r := range s.totp {
		if r.AADVersion == mfa.AADVersionLegacy && r.seq > after.Position() {
			rows = append(rows, r)
		}
	}
	slices.SortFunc(rows, func(a, b *totpRow) int { return cmp.Compare(a.seq, b.seq) })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]mfa.V016Row, 0, len(rows))
	next := after
	for _, r := range rows {
		out = append(out, mfa.V016Row{Ref: mfa.SealedRef{Subject: r.Subject}, Sealed: bytes.Clone(r.Sealed)})
		next = store.RestoreCursor(r.seq)
	}
	return out, next, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, r mfa.Reseal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if r.Ref.Subject.IsZero() || len(r.Old) == 0 || len(r.New) == 0 {
		return false, errInvalidReseal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.totp[r.Ref.Subject]
	if !ok || !bytes.Equal(row.Sealed, r.Old) {
		return false, nil
	}
	row.Sealed = bytes.Clone(r.New)
	row.AADVersion = mfa.AADVersionCurrent
	return true, nil
}

func (s *Store) addV016(sub principal.Subject, sealed []byte, createdAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.totp[sub] = &totpRow{
		seq: s.seq,
		Enrollment: mfa.Enrollment{
			Subject: sub, Sealed: bytes.Clone(sealed), AADVersion: mfa.AADVersionLegacy,
			CreatedAt: createdAt.UTC().Truncate(time.Microsecond),
		},
	}
}
