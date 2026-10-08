// Package memory provides an in-process deployment.Store. It reports store.Ephemeral: the sealed
// values and the instance list are private to the process, so it can never coordinate several
// instances.
package memory

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/deployment"
)

var _ deployment.Store = (*Store)(nil)

// Store is safe for concurrent use.
type Store struct {
	clk       clock.Clock
	mu        sync.Mutex
	values    map[string][]byte
	instances map[uuid.UUID]*deployment.Instance
}

// New returns an empty store that reads the wall clock.
func New() *Store { return NewWithClock(clock.Clock{}) }

// NewWithClock returns an empty store that reads c; the composition root passes the library clock.
func NewWithClock(c clock.Clock) *Store {
	return &Store{clk: c, values: map[string][]byte{}, instances: map[uuid.UUID]*deployment.Instance{}}
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Durability() store.Durability { return store.Ephemeral }

func (s *Store) EraseTenant(ctx context.Context, _ principal.TenantID) error { return ctx.Err() }

func (s *Store) ReapExpired(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	cutoff := s.clk.Now().Add(-deployment.LivenessWindow)
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, in := range s.instances {
		if !in.LastSeenAt.After(cutoff) {
			delete(s.instances, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) GetSealed(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(v), nil
}

func (s *Store) PutSealedIfAbsent(ctx context.Context, key string, sealed []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" || len(sealed) == 0 {
		return false, errors.New("deployment: key and sealed value are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.values[key]; ok {
		return false, nil
	}
	s.values[key] = bytes.Clone(sealed)
	return true, nil
}

func (s *Store) ReplaceSealed(ctx context.Context, key string, r deployment.Replacement) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(r.New) == 0 {
		return false, errors.New("deployment: replacement value is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.values[key]
	if !ok {
		return false, store.ErrNotFound
	}
	if !bytes.Equal(cur, r.Old) {
		return false, nil
	}
	s.values[key] = bytes.Clone(r.New)
	return true, nil
}

func (s *Store) Heartbeat(ctx context.Context, instance uuid.UUID) ([]deployment.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if instance == uuid.Nil {
		return nil, errors.New("deployment: instance id is required")
	}
	now := s.clk.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.instances[instance]
	if !ok || !in.LastSeenAt.After(now.Add(-deployment.LivenessWindow)) {
		in = &deployment.Instance{ID: instance, StartedAt: now}
		s.instances[instance] = in
	}
	in.LastSeenAt = now
	return s.live(now), nil
}

func (s *Store) live(now time.Time) []deployment.Instance {
	cutoff := now.Add(-deployment.LivenessWindow)
	var out []deployment.Instance
	for _, in := range s.instances {
		if in.LastSeenAt.After(cutoff) {
			out = append(out, *in)
		}
	}
	slices.SortFunc(out, func(a, b deployment.Instance) int {
		if c := a.StartedAt.Compare(b.StartedAt); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return out
}
