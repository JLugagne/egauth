package backendtest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/tokens"
)

var (
	// ErrClaimsDown is what Claims returns while failing.
	ErrClaimsDown = errors.New("backendtest: claims source down")
	// ErrOutage is what the sources wrapped by Outage return while it is set.
	ErrOutage = errors.New("backendtest: revocation source down")
)

const defaultClaims = `{"roles":["user"],"groups":["staff"]}`

type claimsMode uint8

const (
	claimsUp claimsMode = iota
	claimsDown
	claimsUnknown
)

// Claims is the session.ClaimsSource of the suite: one JSON object for every subject, switchable
// to failing or to not knowing any subject. It is safe for concurrent use.
type Claims struct {
	mu    sync.Mutex
	value []byte
	mode  claimsMode
}

// NewClaims returns a source answering a small fixed object.
func NewClaims() *Claims { return &Claims{value: []byte(defaultClaims)} }

var _ session.ClaimsSource = (*Claims)(nil)

// ClaimsFor returns the current object, ErrClaimsDown while failing, or session.ErrUnknownSubject.
func (c *Claims) ClaimsFor(context.Context, core.Subject) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.mode {
	case claimsDown:
		return nil, ErrClaimsDown
	case claimsUnknown:
		return nil, session.ErrUnknownSubject
	}
	return slices.Clone(c.value), nil
}

// Set makes the source answer raw and recover from any failure.
func (c *Claims) Set(raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value, c.mode = slices.Clone(raw), claimsUp
}

// Value returns the object the source answers when up.
func (c *Claims) Value() core.SealedClaims {
	c.mu.Lock()
	defer c.mu.Unlock()
	return core.NewSealedClaims(c.value)
}

// Fail makes the source fail until Recover or Set.
func (c *Claims) Fail() { c.setMode(claimsDown) }

// Forget makes the source answer session.ErrUnknownSubject until Recover or Set.
func (c *Claims) Forget() { c.setMode(claimsUnknown) }

// Recover makes the source answer its object again.
func (c *Claims) Recover() { c.setMode(claimsUp) }

func (c *Claims) setMode(m claimsMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = m
}

// Enrollment is the persisted MFA enrollment the backend's MFA decisions must be built from. It
// is safe for concurrent use.
type Enrollment struct {
	mu       sync.Mutex
	enrolled map[principal.Subject][]core.Factor
}

// NewEnrollment returns an enrollment where no subject has a second factor.
func NewEnrollment() *Enrollment {
	return &Enrollment{enrolled: map[principal.Subject][]core.Factor{}}
}

// Enroll records second factors fs for s.
func (e *Enrollment) Enroll(s principal.Subject, fs ...core.Factor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enrolled[s] = append(e.enrolled[s], fs...)
}

// Factors returns the second factors enrolled for s, nil when none.
func (e *Enrollment) Factors(s principal.Subject) []core.Factor {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.enrolled[s])
}

// Events records the events a backend emits. It is safe for concurrent use.
type Events struct {
	mu     sync.Mutex
	counts map[event.Type]int
}

// NewEvents returns an empty recorder.
func NewEvents() *Events { return &Events{counts: map[event.Type]int{}} }

// EmitEvent records e.
func (r *Events) EmitEvent(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[e.Type]++
}

// Count returns how many events of type t were recorded.
func (r *Events) Count(t event.Type) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[t]
}

// Outage makes the revocation sources it wraps fail, change feed and lookups alike, while set. It
// is safe for concurrent use.
type Outage struct {
	down atomic.Bool
}

// Set starts (true) or ends (false) the outage.
func (o *Outage) Set(down bool) { o.down.Store(down) }

// Err returns ErrOutage while the outage lasts, nil otherwise.
func (o *Outage) Err() error {
	if o.down.Load() {
		return ErrOutage
	}
	return nil
}

// Families wraps a family revocation source.
func (o *Outage) Families(src revoke.FamilySource) revoke.FamilySource {
	return flakyFamilies{src: src, o: o}
}

// Epochs wraps an epoch revocation source.
func (o *Outage) Epochs(src revoke.EpochSource) revoke.EpochSource {
	return flakyEpochs{src: src, o: o}
}

type flakyFamilies struct {
	src revoke.FamilySource
	o   *Outage
}

func (f flakyFamilies) FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (tokens.FamilyState, error) {
	if err := f.o.Err(); err != nil {
		return tokens.FamilyState{}, err
	}
	return f.src.FamilyState(ctx, t, family)
}

func (f flakyFamilies) RevocationsSince(ctx context.Context, c store.Cursor) ([]tokens.Revocation, store.Cursor, error) {
	if err := f.o.Err(); err != nil {
		return nil, c, err
	}
	return f.src.RevocationsSince(ctx, c)
}

type flakyEpochs struct {
	src revoke.EpochSource
	o   *Outage
}

func (f flakyEpochs) CurrentEpoch(ctx context.Context, s principal.Subject) (uint64, error) {
	if err := f.o.Err(); err != nil {
		return 0, err
	}
	return f.src.CurrentEpoch(ctx, s)
}

func (f flakyEpochs) EpochsChangedSince(ctx context.Context, c store.Cursor) ([]identity.EpochChange, store.Cursor, error) {
	if err := f.o.Err(); err != nil {
		return nil, c, err
	}
	return f.src.EpochsChangedSince(ctx, c)
}
