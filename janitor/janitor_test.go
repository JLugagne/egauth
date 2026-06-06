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
