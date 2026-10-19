package reap_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/reap"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

type fakeOutbox struct {
	n      atomic.Int64
	err    error
	gate   chan struct{}
	ctxErr bool
}

func (o *fakeOutbox) Retry(ctx context.Context) error {
	o.n.Add(1)
	if o.gate != nil {
		select {
		case <-o.gate:
		case <-ctx.Done():
		}
	}
	if o.ctxErr {
		return ctx.Err()
	}
	return o.err
}

type fakeReaper struct {
	n   atomic.Int64
	err error
}

func (r *fakeReaper) ReapExpired(context.Context) (int64, error) {
	r.n.Add(1)
	return 0, r.err
}

type sink struct {
	mu  sync.Mutex
	got []event.Event
}

func (s *sink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
}

func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.got...)
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func newReaper(t *testing.T, o *fakeOutbox, clk *clock.Test, s *sink, stores ...reap.Store) *reap.Reaper {
	t.Helper()
	r, err := reap.New(reap.Config{Stores: stores, Outbox: o, Clock: clk.Clock(), Events: s})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Stop)
	return r
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	_, err := reap.New(reap.Config{Stores: []reap.Store{{Name: "a"}, {Name: "a", Reaper: &fakeReaper{}}}})
	if !errors.Is(err, reap.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
	_, err = reap.New(reap.Config{Outbox: &fakeOutbox{}, Stores: []reap.Store{{Name: "a", Reaper: &fakeReaper{}}, {Name: "a", Reaper: &fakeReaper{}}}})
	if !errors.Is(err, reap.ErrInvalidConfig) {
		t.Fatalf("repeated name must be rejected, got %v", err)
	}
}

func TestRunOnceRetriesOutboxAndReapsEveryStore(t *testing.T) {
	o, a, b := &fakeOutbox{}, &fakeReaper{}, &fakeReaper{}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{}, reap.Store{Name: "a", Reaper: a}, reap.Store{Name: "b", Reaper: b})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.n.Load() != 1 || a.n.Load() != 1 || b.n.Load() != 1 {
		t.Fatalf("outbox=%d a=%d b=%d", o.n.Load(), a.n.Load(), b.n.Load())
	}
}

func TestFailuresAreEmittedAndOtherStoresStillRun(t *testing.T) {
	boom := errors.New("boom")
	o, a, b := &fakeOutbox{err: boom}, &fakeReaper{err: boom}, &fakeReaper{}
	s := &sink{}
	r := newReaper(t, o, clock.NewTest(time.Now()), s, reap.Store{Name: "a", Reaper: a}, reap.Store{Name: "b", Reaper: b})
	err := r.RunOnce(context.Background())
	if !errors.Is(err, boom) || b.n.Load() != 1 {
		t.Fatalf("err=%v b=%d", err, b.n.Load())
	}
	got := s.all()
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	for _, e := range got {
		if e.Type != event.LifecycleRetry || e.Err.IsZero() {
			t.Fatalf("got %+v", e)
		}
	}
}

func TestPokeIsAsynchronousBoundedByInterval(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{})}
	clk := clock.NewTest(time.Now())
	r := newReaper(t, o, clk, &sink{})
	done := make(chan struct{})
	go func() { r.Poke(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Poke must not block the request")
	}
	eventually(t, func() bool { return o.n.Load() == 1 })
	r.Poke()
	r.Poke()
	time.Sleep(20 * time.Millisecond)
	if o.n.Load() != 1 {
		t.Fatalf("a running pass must not be doubled, got %d", o.n.Load())
	}
	close(o.gate)
	eventually(t, func() bool { return o.n.Load() == 1 })
	time.Sleep(20 * time.Millisecond)
	r.Poke()
	time.Sleep(20 * time.Millisecond)
	if o.n.Load() != 1 {
		t.Fatalf("a pass younger than the interval must not restart, got %d", o.n.Load())
	}
	clk.Advance(reap.RetryInterval)
	r.Poke()
	eventually(t, func() bool { return o.n.Load() == 2 })
}

func TestReapIntervalGatesStoreReaping(t *testing.T) {
	o, a := &fakeOutbox{}, &fakeReaper{}
	clk := clock.NewTest(time.Now())
	r := newReaper(t, o, clk, &sink{}, reap.Store{Name: "a", Reaper: a})
	r.Poke()
	eventually(t, func() bool { return a.n.Load() == 1 })
	clk.Advance(reap.RetryInterval)
	r.Poke()
	eventually(t, func() bool { return o.n.Load() == 2 })
	if a.n.Load() != 1 {
		t.Fatalf("stores reap only every ReapInterval, got %d", a.n.Load())
	}
	clk.Advance(reap.ReapInterval)
	r.Poke()
	eventually(t, func() bool { return a.n.Load() == 2 })
}

func TestStartRunsAtOnceAndStopIsFinalAndWaits(t *testing.T) {
	o := &fakeOutbox{}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{})
	r.Start()
	r.Start()
	eventually(t, func() bool { return o.n.Load() >= 1 })
	r.Stop()
	r.Stop()
	n := o.n.Load()
	r.Start()
	r.Poke()
	time.Sleep(20 * time.Millisecond)
	if o.n.Load() != n {
		t.Fatal("nothing runs after Stop")
	}
}

func TestStopCancelsARunningPass(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{})}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{})
	r.Start()
	eventually(t, func() bool { return o.n.Load() == 1 })
	done := make(chan struct{})
	go func() { r.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop must cancel and join the pass")
	}
}

func TestStopDuringAPassEmitsNoRetryEvent(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{}), ctxErr: true}
	s := &sink{}
	r := newReaper(t, o, clock.NewTest(time.Now()), s)
	r.Start()
	eventually(t, func() bool { return o.n.Load() == 1 })
	r.Stop()
	if got := s.all(); len(got) != 0 {
		t.Fatalf("a clean shutdown must not raise an outage signal, got %d events", len(got))
	}
}

func TestRetryEventsScopesToSubjectAndCarriesAttempts(t *testing.T) {
	s := &sink{}
	sub := principal.Subject{Tenant: mustTenant(t), User: uuid.New()}
	reap.RetryEvents(s).ReportRetry(context.Background(), lifecycle.Retry{
		Component: identity.ComponentMFA, Event: identity.EventDelete, Subject: sub, Attempts: 3, Err: errors.New("x"),
	})
	got := s.all()
	if len(got) != 1 || got[0].Type != event.LifecycleRetry || got[0].UserID != sub.User.String() || got[0].TenantID != sub.Tenant.String() || got[0].Err.IsZero() {
		t.Fatalf("got %+v", got)
	}
	reap.RetryEvents(nil).ReportRetry(context.Background(), lifecycle.Retry{})
}

func mustTenant(t *testing.T) principal.TenantID {
	t.Helper()
	id, err := principal.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRunOnceAfterStopDoesNotRunAPass(t *testing.T) {
	o := &fakeOutbox{}
	rp := &fakeReaper{}
	r := newReaper(t, o, clock.NewTest(clock.Clock{}.Now()), &sink{}, reap.Store{Name: "s", Reaper: rp})
	r.Stop()
	if err := r.RunOnce(context.Background()); !errors.Is(err, reap.ErrStopped) {
		t.Fatalf("got %v, want ErrStopped", err)
	}
	if o.n.Load() != 0 || rp.n.Load() != 0 {
		t.Fatalf("a stopped reaper ran a pass: outbox %d reapers %d", o.n.Load(), rp.n.Load())
	}
}

func TestStopCancelsAndJoinsARunOnceOfTheCaller(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{})}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{})
	ran := make(chan error, 1)
	go func() { ran <- r.RunOnce(context.Background()) }()
	eventually(t, func() bool { return o.n.Load() == 1 })
	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	select {
	case <-stopped:
		select {
		case err := <-ran:
			t.Logf("RunOnce returned %v", err)
		default:
			t.Fatal("Stop returned while a RunOnce pass was still running against the stores")
		}
	case <-time.After(5 * time.Second):
		close(o.gate)
		t.Fatal("Stop neither cancelled nor joined the RunOnce pass")
	}
}

func TestRunOnceGivesUpWhenItsContextEndsWhileAPassRuns(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{})}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{})
	go func() { _ = r.RunOnce(context.Background()) }()
	eventually(t, func() bool { return o.n.Load() == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.RunOnce(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RunOnce = %v, want its context's error", err)
		}
	case <-time.After(2 * time.Second):
		close(o.gate)
		t.Fatal("RunOnce kept waiting for the running pass after its context ended")
	}
	close(o.gate)
}

func TestRunOnceWaitingForAPassReturnsErrStoppedWhenStopRuns(t *testing.T) {
	o := &fakeOutbox{gate: make(chan struct{})}
	r := newReaper(t, o, clock.NewTest(time.Now()), &sink{})
	go func() { _ = r.RunOnce(context.Background()) }()
	eventually(t, func() bool { return o.n.Load() == 1 })
	done := make(chan error, 1)
	go func() { done <- r.RunOnce(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	r.Stop()
	select {
	case err := <-done:
		if !errors.Is(err, reap.ErrStopped) {
			t.Fatalf("RunOnce waiting while Stop ran = %v, want reap.ErrStopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunOnce kept waiting after Stop")
	}
}
