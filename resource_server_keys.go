package egauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

const (
	jwksMaxAge       = time.Minute
	jwksMinRefresh   = 10 * time.Second
	jwksFetchTimeout = 10 * time.Second
)

var errUnknownKeyID = errors.New("egauth: key id is not in the issuer's JWKS")

type jwksFlight struct {
	done chan struct{}
	err  error
}

type jwksSource struct {
	fetch  func(context.Context) ([]signing.Verifier, error)
	clk    clock.Clock
	tenant string

	mu      sync.Mutex
	keys    map[string]signing.Verifier
	loaded  time.Time
	failed  time.Time
	failure error
	flight  *jwksFlight
}

func (s *jwksSource) refresh(ctx context.Context, now time.Time) error {
	vs, err := s.fetch(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.record(vs, err, now)
}

func (s *jwksSource) record(vs []signing.Verifier, err error, now time.Time) error {
	if err != nil {
		s.failed, s.failure = now, err
		return err
	}
	keys := make(map[string]signing.Verifier, len(vs))
	for _, v := range vs {
		keys[v.KeyID()] = v
	}
	s.keys, s.loaded, s.failed, s.failure = keys, now, time.Time{}, nil
	return nil
}

func (s *jwksSource) startFlight(ctx context.Context, now time.Time) *jwksFlight {
	if s.flight != nil {
		return s.flight
	}
	f := &jwksFlight{done: make(chan struct{})}
	s.flight = f
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksFetchTimeout)
	go func() {
		defer cancel()
		vs, err := s.fetch(detached)
		s.mu.Lock()
		f.err = s.record(vs, err, now)
		s.flight = nil
		s.mu.Unlock()
		close(f.done)
	}()
	return f
}

func (s *jwksSource) Verifier(ctx context.Context, tenant principal.TenantID, kid string) (signing.Verifier, error) {
	if tenant.String() != s.tenant {
		return signing.Verifier{}, errUnknownKeyID
	}
	s.mu.Lock()
	now := s.clk.Now()
	age := now.Sub(s.loaded)
	stale := age >= jwksMaxAge || age < 0
	v, known := s.keys[kid]
	if known && !stale {
		s.mu.Unlock()
		return v, nil
	}
	if !known && !stale && age < jwksMinRefresh {
		s.mu.Unlock()
		return signing.Verifier{}, errUnknownKeyID
	}
	if s.flight == nil && !s.failed.IsZero() && now.Sub(s.failed) >= 0 && now.Sub(s.failed) < jwksMinRefresh {
		failure := s.failure
		s.mu.Unlock()
		return signing.Verifier{}, errors.Join(revoke.ErrUnavailable, failure)
	}
	f := s.startFlight(ctx, now)
	s.mu.Unlock()
	select {
	case <-f.done:
	case <-ctx.Done():
		return signing.Verifier{}, errors.Join(revoke.ErrUnavailable, ctx.Err())
	}
	if f.err != nil {
		return signing.Verifier{}, errors.Join(revoke.ErrUnavailable, f.err)
	}
	s.mu.Lock()
	v, known = s.keys[kid]
	s.mu.Unlock()
	if !known {
		return signing.Verifier{}, errUnknownKeyID
	}
	return v, nil
}

func (s *jwksSource) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys) == 0
}
