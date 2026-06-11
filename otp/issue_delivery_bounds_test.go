package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestIssueHandler_DeliveryConcurrencyBound is the regression test for the audit finding:
// IssueHandler previously spawned an unbounded goroutine per request with no concurrency cap
// and no per-delivery timeout.  After the fix, WithMaxConcurrentDeliveries limits the number
// of in-flight delivery goroutines; excess requests are DROPPED rather than queued or spawned.
func TestIssueHandler_DeliveryConcurrencyBound(t *testing.T) {
	const cap = 3
	const total = 20

	svc := otp.NewService(memory.NewStore())
	subject := uuid.New()

	// gate blocks every delivery goroutine until we release it, so we can count in-flight slots.
	gate := make(chan struct{})
	var inFlight int64
	var peak int64

	// The handler's semaphore pins every acquired slot until gate closes, so excess requests are
	// dropped and exactly `cap` delivery goroutines ever run. deliveries lets the test wait for all
	// of them to finish before reading peak, establishing the happens-before that a bare sleep does
	// not — without it the read of peak below races the atomic CAS writes here.
	var deliveries sync.WaitGroup
	deliveries.Add(cap)

	deliver := func(_ context.Context, _ *otp.Challenge) error {
		defer deliveries.Done()
		cur := atomic.AddInt64(&inFlight, 1)
		// Track the peak in-flight count.
		for {
			old := atomic.LoadInt64(&peak)
			if cur <= old || atomic.CompareAndSwapInt64(&peak, old, cur) {
				break
			}
		}
		<-gate // hold the slot until released
		atomic.AddInt64(&inFlight, -1)
		return nil
	}

	h := otp.IssueHandler(
		svc,
		deliver,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
			return subject, true
		}),
		otp.WithMaxConcurrentDeliveries(cap),
		otp.WithDeliveryTimeout(5*time.Second),
	)

	// Fire total concurrent HTTP requests; each responds immediately (204).
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/otp/issue", nil))
			assert.Equal(t, http.StatusNoContent, rec.Code)
		}()
	}
	wg.Wait() // all HTTP responses are back

	// Release all delivery goroutines and wait for every one to return; deliveries.Wait()
	// happens-after each deliver's peak update, so the read below is race-free.
	close(gate)
	deliveries.Wait()

	// The peak number of simultaneous in-flight deliveries must not exceed the cap.
	assert.LessOrEqual(t, atomic.LoadInt64(&peak), int64(cap),
		"IssueHandler must not spawn more than WithMaxConcurrentDeliveries(%d) concurrent delivery goroutines", cap)
}

// TestIssueHandler_DeliveryTimeout verifies that a hung deliver callback is cancelled after the
// configured timeout, preventing goroutine leaks when the Mailer/SMSSender stalls.
func TestIssueHandler_DeliveryTimeout(t *testing.T) {
	svc := otp.NewService(memory.NewStore())
	subject := uuid.New()

	const timeout = 50 * time.Millisecond

	// deliver blocks until its context is cancelled (simulating a hung backend).
	cancelled := make(chan struct{})
	deliver := func(ctx context.Context, _ *otp.Challenge) error {
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}

	h := otp.IssueHandler(
		svc,
		deliver,
		otp.WithSubjectResolver(func(r *http.Request) (uuid.UUID, bool) {
			return subject, true
		}),
		otp.WithDeliveryTimeout(timeout),
		otp.WithMaxConcurrentDeliveries(10),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/otp/issue", nil))
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// The delivery context must be cancelled within a generous multiple of the configured timeout.
	select {
	case <-cancelled:
		// good: the timeout fired and unblocked the hung delivery
	case <-time.After(5 * time.Second):
		t.Fatal("deliver callback was never cancelled: WithDeliveryTimeout did not apply a deadline")
	}
}
