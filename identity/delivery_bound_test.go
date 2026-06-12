package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fireReset POSTs a password-reset request for the given email against handler h.
func fireReset(h http.HandlerFunc, email string) {
	body := url.Values{"email": {email}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(httptest.NewRecorder(), req)
}

// TestDispatchDeliveryBounded fires many concurrent Request* calls for a known account through a
// Mailer that blocks on a release latch, recording the maximum concurrency it ever observes. The
// in-flight deliveries must never exceed the configured cap, and every over-cap request must
// surface a DeliveryFailed event (the drop is observable like a Mailer outage).
func TestDispatchDeliveryBounded(t *testing.T) {
	const (
		cap     = 8
		nBursts = 200
	)
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}

	release := make(chan struct{}) // deliveries block here until the test lets them finish
	var inFlight int32
	var maxInFlight int32
	mailer := identity.Mailer{
		PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
			cur := atomic.AddInt32(&inFlight, 1)
			for {
				old := atomic.LoadInt32(&maxInFlight)
				if cur <= old || atomic.CompareAndSwapInt32(&maxInFlight, old, cur) {
					break
				}
			}
			<-release
			atomic.AddInt32(&inFlight, -1)
			return nil
		},
	}

	sink := &captureSink{}
	h := identity.RequestPasswordResetHandler(svc, mailer,
		identity.WithDeliveryConcurrency(cap),
		identity.WithHandlerEventSink(sink))

	var wg sync.WaitGroup
	for range nBursts {
		wg.Go(func() {
			fireReset(h, "u@example.com")
		})
	}
	wg.Wait() // all requests have returned (delivery dispatch is non-blocking)

	// The cap saturates while deliveries block; over-cap requests are dropped and emit an event.
	// Wait until exactly `cap` deliveries are parked AND all the drops have been recorded.
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inFlight) == int32(cap) &&
			sink.count(event.DeliveryFailed) == nBursts-cap
	}, 2*time.Second, 5*time.Millisecond,
		"exactly cap deliveries should be in-flight and the rest dropped with a DeliveryFailed event")

	// The hard invariant: observed concurrency never exceeded the configured cap.
	assert.LessOrEqual(t, atomic.LoadInt32(&maxInFlight), int32(cap),
		"in-flight deliveries must never exceed the configured concurrency cap")

	// Drain the parked deliveries so the goroutines exit cleanly under -race.
	close(release)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&inFlight) == 0 },
		2*time.Second, 5*time.Millisecond, "all in-flight deliveries should drain")
}

// TestDispatchDeliveryDropEmitsEvent asserts the dropped delivery carries the documented
// ErrDeliveryDropped sentinel so consumers can distinguish a cap-drop from a backend outage.
func TestDispatchDeliveryDropEmitsEvent(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	mailer := identity.Mailer{
		PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
			entered <- struct{}{} // signal the slot is taken
			<-release             // pin the single slot
			return nil
		},
	}

	sink := &captureSink{}
	h := identity.RequestPasswordResetHandler(svc, mailer,
		identity.WithDeliveryConcurrency(1),
		identity.WithHandlerEventSink(sink))

	// First request takes the only slot and blocks inside the Mailer.
	go fireReset(h, "u@example.com")
	<-entered
	// A second request now finds the semaphore full and must be dropped with an event.
	fireReset(h, "u@example.com")
	require.Eventually(t, func() bool { return sink.count(event.DeliveryFailed) >= 1 },
		2*time.Second, time.Millisecond, "an over-cap delivery must surface a DeliveryFailed event")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var found bool
	for _, e := range sink.events {
		if e.Type == event.DeliveryFailed {
			assert.ErrorIs(t, e.Err, identity.ErrDeliveryDropped,
				"a cap-drop must carry ErrDeliveryDropped")
			assert.Equal(t, user.ID.String(), e.UserID)
			found = true
			break
		}
	}
	assert.True(t, found)
}

// TestDispatchDeliveryTimeout asserts that a delivery exceeding its per-delivery timeout is
// abandoned (the delivery context is cancelled) and surfaces a DeliveryFailed event.
func TestDispatchDeliveryTimeout(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}

	// The Mailer blocks on the delivery context: it returns the context error when the
	// per-delivery timeout fires, so a hung backend cannot pin the slot forever.
	mailer := identity.Mailer{
		PasswordReset: func(ctx context.Context, _ identity.PasswordResetMail) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}

	sink := &captureSink{}
	h := identity.RequestPasswordResetHandler(svc, mailer,
		identity.WithDeliveryTimeout(20*time.Millisecond),
		identity.WithHandlerEventSink(sink))

	rec := httptest.NewRecorder()
	body := url.Values{"email": {"u@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)

	// The request returns immediately (delivery is off the response path) and stays uniform.
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Eventually(t, func() bool { return sink.has(event.DeliveryFailed) }, time.Second, 5*time.Millisecond,
		"a delivery that exceeds its timeout must be abandoned and surface a DeliveryFailed event")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, e := range sink.events {
		if e.Type == event.DeliveryFailed {
			assert.ErrorIs(t, e.Err, context.DeadlineExceeded,
				"the abandoned delivery should carry the timeout error")
		}
	}
}

// TestDispatchDeliveryTimeoutDoesNotCancelOnRequestEnd asserts the delivery context is detached
// from the request: the request finishing must NOT cancel an in-flight delivery (durability), only
// the per-delivery timeout bounds it.
func TestDispatchDeliveryTimeoutDoesNotCancelOnRequestEnd(t *testing.T) {
	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}

	started := make(chan struct{})
	proceed := make(chan struct{})
	ctxErrCh := make(chan error, 1) // hands the observed ctx.Err() back to the test race-free
	mailer := identity.Mailer{
		PasswordReset: func(ctx context.Context, _ identity.PasswordResetMail) error {
			close(started)
			<-proceed // hold past the request returning
			ctxErrCh <- ctx.Err()
			return nil
		},
	}

	// Generous timeout so the timeout itself does not fire during the window we observe.
	h := identity.RequestPasswordResetHandler(svc, mailer,
		identity.WithDeliveryTimeout(10*time.Second))

	rec := httptest.NewRecorder()
	body := url.Values{"email": {"u@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req) // returns while the delivery is still parked in started/proceed

	<-started
	require.Equal(t, http.StatusNoContent, rec.Code)
	close(proceed)
	select {
	case err := <-ctxErrCh:
		// The delivery observed a live (non-cancelled) context even though the request returned.
		assert.NoError(t, err, "request finishing must not cancel the detached delivery")
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not run after the request returned")
	}
}

// TestDeliveryConcurrencyDefault documents the default cap value via the option/config: with no
// option set the handler must bound at DefaultDeliveryConcurrency. We assert the constant and then
// behaviorally confirm the default semaphore caps at that value.
func TestDeliveryConcurrencyDefault(t *testing.T) {
	assert.Equal(t, 64, identity.DefaultDeliveryConcurrency, "documented default delivery concurrency")
	assert.Equal(t, 30*time.Second, identity.DefaultDeliveryTimeout, "documented default delivery timeout")

	user := &identity.User{ID: uuid.New(), Email: "u@example.com"}
	svc := &servicetest.MockService{
		RequestPasswordResetFunc: func(_ context.Context, _ string, _ string) (string, *identity.User, error) {
			return "sel.ver", user, nil
		},
	}

	release := make(chan struct{})
	var inFlight int32
	var maxInFlight int32
	mailer := identity.Mailer{
		PasswordReset: func(_ context.Context, _ identity.PasswordResetMail) error {
			cur := atomic.AddInt32(&inFlight, 1)
			for {
				old := atomic.LoadInt32(&maxInFlight)
				if cur <= old || atomic.CompareAndSwapInt32(&maxInFlight, old, cur) {
					break
				}
			}
			<-release
			atomic.AddInt32(&inFlight, -1)
			return nil
		},
	}

	// No WithDeliveryConcurrency: the default cap must apply.
	sink := &captureSink{}
	h := identity.RequestPasswordResetHandler(svc, mailer, identity.WithHandlerEventSink(sink))

	const nBursts = identity.DefaultDeliveryConcurrency + 50
	var wg sync.WaitGroup
	for range nBursts {
		wg.Go(func() {
			fireReset(h, "u@example.com")
		})
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&inFlight) == int32(identity.DefaultDeliveryConcurrency) &&
			sink.count(event.DeliveryFailed) == nBursts-identity.DefaultDeliveryConcurrency
	}, 2*time.Second, 5*time.Millisecond)
	assert.LessOrEqual(t, atomic.LoadInt32(&maxInFlight), int32(identity.DefaultDeliveryConcurrency),
		"the default cap must bound in-flight deliveries")

	close(release)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&inFlight) == 0 },
		2*time.Second, 5*time.Millisecond)
}
