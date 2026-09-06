package janitor_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/janitor"
)

// TestJanitorCallsCallback proves the janitor invokes fn at least once within a short
// bounded window and then stops calling it after Stop.
func TestJanitorCallsCallback(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	ctx := context.Background()
	j := janitor.Start(ctx, 10*time.Millisecond, func() {
		calls.Add(1)
	})

	// Wait until at least 3 ticks have been observed (bounded: ≤ 500 ms).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && calls.Load() < 3 {
		time.Sleep(time.Millisecond)
	}

	// Record call count just before Stop to prove calls were made.
	before := calls.Load()
	if before < 1 {
		t.Fatalf("expected at least 1 call before Stop, got %d", before)
	}

	// Stop must block until the goroutine exits.
	j.Stop()

	// After Stop, allow a brief window for any in-flight tick to land, then assert
	// the count has not grown further — the goroutine must be gone.
	time.Sleep(50 * time.Millisecond)
	after := calls.Load()

	// at most one extra call could have been in flight at the moment of Stop
	if after > before+1 {
		t.Fatalf("calls continued after Stop: before=%d after=%d", before, after)
	}
}

// TestJanitorStopsOnContextCancel proves the janitor exits when its parent context is
// cancelled, without an explicit Stop call.
func TestJanitorStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	ctx, cancel := context.WithCancel(context.Background())
	janitor.Start(ctx, 10*time.Millisecond, func() {
		calls.Add(1)
	})

	// Let a few ticks happen.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Capture count right after cancel and again after a quiet window.
	snapshot := calls.Load()
	time.Sleep(50 * time.Millisecond)
	final := calls.Load()

	if final > snapshot+1 {
		t.Fatalf("calls continued after context cancel: snapshot=%d final=%d", snapshot, final)
	}
}

// TestJanitorStopIsIdempotent proves calling Stop multiple times does not panic or block.
func TestJanitorStopIsIdempotent(t *testing.T) {
	t.Parallel()

	j := janitor.Start(context.Background(), time.Hour, func() {})
	j.Stop()
	j.Stop() // must not panic or deadlock
}

// TestJanitorStopAfterContextCancel proves Stop is safe even when the context was already
// cancelled by the parent (double-stop scenario via two paths).
func TestJanitorStopAfterContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	j := janitor.Start(ctx, time.Hour, func() {})
	cancel()
	// Give the goroutine a moment to notice the cancellation.
	time.Sleep(10 * time.Millisecond)
	j.Stop() // must not panic or block
}

func TestJanitor_WithPanicHandler(t *testing.T) {
	t.Parallel()

	var panicked atomic.Bool
	var handled atomic.Bool
	var val atomic.Value

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := janitor.Start(ctx, 5*time.Millisecond, func() {
		if !panicked.Swap(true) {
			panic("boom")
		}
	}, janitor.WithPanicHandler(func(recovered any) {
		handled.Store(true)
		val.Store(recovered)
	}))
	defer j.Stop()

	time.Sleep(30 * time.Millisecond)
	if !handled.Load() {
		t.Fatal("expected panic to be handled by WithPanicHandler")
	}
	if val.Load() != "boom" {
		t.Fatalf("expected panic value 'boom', got %v", val.Load())
	}
}

func TestJanitor_WithOnError(t *testing.T) {
	t.Parallel()

	var panicked atomic.Bool
	var errHandled atomic.Bool
	var errVal atomic.Value

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := janitor.Start(ctx, 5*time.Millisecond, func() {
		if !panicked.Swap(true) {
			panic("error boom")
		}
	}, janitor.WithOnError(func(err error) {
		errHandled.Store(true)
		errVal.Store(err)
	}))
	defer j.Stop()

	time.Sleep(30 * time.Millisecond)
	if !errHandled.Load() {
		t.Fatal("expected error to be handled by WithOnError")
	}
	if errVal.Load() == nil {
		t.Fatal("expected non-nil error in WithOnError")
	}
}

func TestNew_RejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, err := janitor.New(ctx, 0, func() {})
	if err == nil {
		t.Fatal("expected error for zero interval")
	}
	_, err = janitor.New(ctx, -time.Second, func() {})
	if err == nil {
		t.Fatal("expected error for negative interval")
	}
}

func TestStart_NonPositiveIntervalDefaultsToSafeInterval(t *testing.T) {
	t.Parallel()

	var count atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := janitor.Start(ctx, 0, func() {
		count.Add(1)
	})
	defer j.Stop()

	time.Sleep(50 * time.Millisecond)
	if count.Load() > 1 {
		t.Fatalf("expected safe interval, but executed %d times in 50ms", count.Load())
	}
}

func TestJanitor_StopContext_Success(t *testing.T) {
	t.Parallel()

	j := janitor.Start(context.Background(), time.Hour, func() {})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := j.StopContext(ctx)
	if err != nil {
		t.Fatalf("expected nil error on clean stop, got %v", err)
	}
}

func TestJanitor_StopContext_BoundedTimeout(t *testing.T) {
	t.Parallel()

	blocker := make(chan struct{})
	started := make(chan struct{})

	j := janitor.Start(context.Background(), time.Millisecond, func() {
		close(started)
		<-blocker
	})

	<-started

	stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := j.StopContext(stopCtx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}

	close(blocker)

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
	defer cleanupCancel()

	if err := j.StopContext(cleanupCtx); err != nil {
		t.Fatalf("expected nil error after unblocking, got %v", err)
	}
}

func TestJanitor_StopContext_ContextCancelled(t *testing.T) {
	t.Parallel()

	blocker := make(chan struct{})
	started := make(chan struct{})

	j := janitor.Start(context.Background(), time.Millisecond, func() {
		close(started)
		<-blocker
	})

	<-started

	stopCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := j.StopContext(stopCtx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	close(blocker)
	_ = j.StopContext(context.Background())
}

func TestJanitor_WithStopTimeout(t *testing.T) {
	t.Parallel()

	blocker := make(chan struct{})
	started := make(chan struct{})

	j := janitor.Start(context.Background(), time.Millisecond, func() {
		close(started)
		<-blocker
	}, janitor.WithStopTimeout(30*time.Millisecond))

	<-started

	start := time.Now()
	j.Stop() // Should return after ~30ms timeout rather than blocking indefinitely
	elapsed := time.Since(start)

	if elapsed < 20*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("expected Stop() to return in ~30ms, took %v", elapsed)
	}

	close(blocker)
}

func TestJanitor_StopContext_Idempotent(t *testing.T) {
	t.Parallel()

	j := janitor.Start(context.Background(), time.Hour, func() {})
	if err := j.StopContext(context.Background()); err != nil {
		t.Fatalf("first StopContext failed: %v", err)
	}
	if err := j.StopContext(context.Background()); err != nil {
		t.Fatalf("second StopContext failed: %v", err)
	}
}
