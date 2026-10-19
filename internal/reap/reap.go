// Package reap owns background maintenance: it calls every store.Reaper and retries the lifecycle
// outbox, on a background ticker and opportunistically from the request path, so a runtime that
// freezes goroutines between requests (serverless) still reaps (DESIGN §3.1, T-20). Every failure is
// emitted as event.LifecycleRetry; none is swallowed.
package reap

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/store"
)

const (
	// RetryInterval is how often the outbox is retried, and the age of the last pass past which
	// Poke starts one.
	RetryInterval = 10 * time.Second
	// ReapInterval is how often every store.Reaper runs.
	ReapInterval = 5 * time.Minute
	// PassTimeout bounds one pass, outbox retry and reaping together.
	PassTimeout = 30 * time.Second
)

var (
	// ErrInvalidConfig is returned by New, joined with one error per problem.
	ErrInvalidConfig = errors.New("reap: invalid configuration")
	// ErrStopped is returned by RunOnce after Stop.
	ErrStopped = errors.New("reap: stopped")
)

// Store is one store.Reaper with the name its failures are reported under.
type Store struct {
	Name   string
	Reaper store.Reaper
}

// Outbox is the lifecycle outbox retry pass (lifecycle.Dispatcher.Retry).
type Outbox interface {
	Retry(ctx context.Context) error
}

// Config is what New needs. Outbox and every Store are required; a nil Events drops the failure
// events. The zero Clock reads the wall clock; the composition root passes the library clock.
type Config struct {
	Stores []Store
	Outbox Outbox
	Clock  clock.Clock
	Events event.Sink
}

// Reaper runs the passes. It is safe for concurrent use. Its goroutines live from Start, or from a
// Poke, until Stop; no request context governs them.
type Reaper struct {
	stores []Store
	outbox Outbox
	clock  clock.Clock
	events event.Sink

	base   context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	pass chan struct{}

	mu        sync.Mutex
	started   bool
	stopped   bool
	lastPass  time.Time
	lastReap  time.Time
	triggered bool
}

// New validates cfg and returns a stopped Reaper. It returns ErrInvalidConfig for a nil Outbox, a
// nil Reaper or an empty or repeated Name.
func New(cfg Config) (*Reaper, error) {
	var errs []error
	if !present(cfg.Outbox) {
		errs = append(errs, errors.New("outbox is required"))
	}
	names := map[string]bool{}
	for i, s := range cfg.Stores {
		switch {
		case !present(s.Reaper):
			errs = append(errs, errors.New("store "+s.Name+" has no reaper"))
		case s.Name == "" || names[s.Name]:
			errs = append(errs, errors.New("store name "+s.Name+" is empty or repeated at "+strconv.Itoa(i)))
		}
		names[s.Name] = true
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	base, cancel := context.WithCancel(context.Background())
	return &Reaper{
		stores: append([]Store(nil), cfg.Stores...),
		outbox: cfg.Outbox,
		clock:  cfg.Clock,
		events: cfg.Events,
		base:   base,
		cancel: cancel,
		pass:   make(chan struct{}, 1),
	}, nil
}

// Start runs a pass at once, then every RetryInterval, until Stop. It is idempotent; after Stop it
// does nothing.
func (r *Reaper) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.stopped {
		return
	}
	r.started = true
	r.wg.Add(1)
	go r.loop()
}

// Stop cancels the running passes and waits for every goroutine of the Reaper. It is idempotent
// and final: Start and Poke do nothing and RunOnce fails afterwards.
func (r *Reaper) Stop() {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}

// Poke is the opportunistic pass of the request path: when the last pass is older than
// RetryInterval and none is running or already triggered, it starts one in the background and
// returns at once. It never blocks the request.
func (r *Reaper) Poke() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.triggered || (!r.lastPass.IsZero() && r.clock.Since(r.lastPass) < RetryInterval) {
		return
	}
	r.triggered = true
	r.wg.Go(func() {
		defer r.untrigger()
		r.tryPass(false)
	})
}

// RunOnce runs one pass now, waiting for a running one unless ctx ends first (ctx.Err()): it retries the outbox and runs every store
// Reaper. The pass is bounded by PassTimeout and cancelled by Stop, which waits for it. It returns
// every failure joined, after emitting each as event.LifecycleRetry, and ErrStopped once Stop was
// called.
func (r *Reaper) RunOnce(ctx context.Context) error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return ErrStopped
	}
	r.wg.Add(1)
	r.mu.Unlock()
	defer r.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, PassTimeout)
	defer cancel()
	defer context.AfterFunc(r.base, cancel)()
	select {
	case r.pass <- struct{}{}:
	case <-ctx.Done():
		if r.base.Err() != nil {
			return ErrStopped
		}
		return ctx.Err()
	}
	defer func() { <-r.pass }()
	if r.base.Err() != nil {
		return ErrStopped
	}
	return r.run(ctx, true)
}

func (r *Reaper) untrigger() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.triggered = false
}

func (r *Reaper) loop() {
	defer r.wg.Done()
	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()
	for {
		r.tryPass(false)
		select {
		case <-r.base.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Reaper) tryPass(force bool) {
	select {
	case r.pass <- struct{}{}:
	default:
		return
	}
	defer func() { <-r.pass }()
	if r.base.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.base, PassTimeout)
	defer cancel()
	_ = r.run(ctx, force)
}

func (r *Reaper) run(ctx context.Context, force bool) error {
	now := r.clock.Now()
	r.mu.Lock()
	r.lastPass = now
	reap := force || r.lastReap.IsZero() || now.Sub(r.lastReap) >= ReapInterval
	if reap {
		r.lastReap = now
	}
	r.mu.Unlock()
	var errs []error
	if err := r.outbox.Retry(ctx); err != nil {
		r.emit(ctx, "outbox", err)
		errs = append(errs, err)
	}
	if !reap {
		return errors.Join(errs...)
	}
	for _, s := range r.stores {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		if _, err := s.Reaper.ReapExpired(ctx); err != nil {
			err = errors.Join(errors.New("reap: "+s.Name), err)
			r.emit(ctx, "reap_"+s.Name, err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Reaper) emit(ctx context.Context, reason string, err error) {
	if r.base.Err() != nil && errors.Is(err, context.Canceled) {
		return
	}
	_ = audit.Emit(context.WithoutCancel(ctx), r.events, event.LifecycleRetry, audit.Scope{}, audit.Detail{Reason: reason}, err)
}

// RetryEvents reports every deferred outbox delivery as event.LifecycleRetry to sink, scoped to
// the row's subject, with the component and event as reason and the attempt count. A nil sink
// drops them.
func RetryEvents(sink event.Sink) lifecycle.RetryReporter {
	return retryEvents{sink: sink}
}

type retryEvents struct {
	sink event.Sink
}

func (e retryEvents) ReportRetry(ctx context.Context, r lifecycle.Retry) {
	var scope audit.Scope
	if !r.Subject.IsZero() {
		scope = audit.Scope{TenantID: r.Subject.Tenant.String(), UserID: r.Subject.User.String()}
	}
	_ = audit.Emit(ctx, e.sink, event.LifecycleRetry, scope, audit.Detail{Reason: r.Component.String() + "." + r.Event.String()}, r.Err,
		audit.A(event.KeyCount, r.Attempts))
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}
