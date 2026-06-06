// Package janitor provides a lightweight, optional ticker-based eviction helper for
// egauth's in-memory stores and rate-limit buckets.
//
// # Why you need this in production
//
// The in-memory stores in [github.com/JLugagne/egauth/sessions/memory],
// [github.com/JLugagne/egauth/otp/memory], and the [github.com/JLugagne/egauth/ratelimit]
// TokenBucket all grow without bound until a periodic eviction call is made:
//
//   - sessions/memory.Store.DeleteExpired — purges expired session rows
//   - otp/memory.Store.DeleteExpired     — purges expired OTP codes
//   - ratelimit.TokenBucket.Cleanup      — drops fully-refilled rate-limit buckets
//
// Any production deployment using these in-memory backends MUST schedule periodic
// eviction; failing to do so leaks memory proportional to load and creates a trivial
// denial-of-service vector (a flood of unique keys/IPs/OTPs grows the map indefinitely).
//
// # Usage
//
// Start starts a background goroutine that calls fn every interval and stops when ctx
// is cancelled or [Janitor.Stop] is called:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	sessStore := memory.NewStore()
//	j := janitor.Start(ctx, 5*time.Minute, func() {
//	    sessStore.DeleteExpired(context.Background(), tenantID)
//	})
//	defer j.Stop()
//
// The same pattern works for otp/memory and ratelimit.TokenBucket:
//
//	otpStore := otpmemory.NewStore()
//	janitor.Start(ctx, 5*time.Minute, func() {
//	    otpStore.DeleteExpired(context.Background(), tenantID)
//	})
//
//	tb := ratelimit.NewTokenBucket(10, time.Second)
//	janitor.Start(ctx, time.Minute, func() {
//	    tb.Cleanup()
//	})
//
// # Multi-tenant deployments
//
// When running multiple tenants you can fan out inside a single janitor goroutine:
//
//	janitor.Start(ctx, 5*time.Minute, func() {
//	    for _, tid := range tenantIDs() {
//	        sessStore.DeleteExpired(context.Background(), tid)
//	    }
//	})
//
// # Stopping
//
// [Janitor.Stop] cancels the janitor goroutine and blocks until it exits. It is
// idempotent — calling Stop more than once is safe. Cancelling the parent context
// passed to [Start] also stops the janitor (Stop need not be called in that case, but
// is harmless).
package janitor

import (
	"context"
	"sync"
	"time"
)

// Janitor manages a single background goroutine that periodically calls a cleanup
// function. Create one via [Start].
type Janitor struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// Start launches a background goroutine that calls fn every interval. The goroutine
// stops when ctx is cancelled or when [Janitor.Stop] is called — whichever comes first.
// fn is called in the goroutine, not on the caller's goroutine; fn must be safe to call
// concurrently with other operations on the store it wraps.
//
// interval is floored at 1ns to avoid a busy spin on a zero or negative value.
func Start(ctx context.Context, interval time.Duration, fn func()) *Janitor {
	if interval <= 0 {
		interval = time.Nanosecond
	}

	ctx, cancel := context.WithCancel(ctx)
	j := &Janitor{
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(j.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fn()
			}
		}
	}()

	return j
}

// Stop cancels the janitor goroutine and blocks until it exits. It is idempotent.
func (j *Janitor) Stop() {
	j.once.Do(func() {
		j.cancel()
		<-j.done
	})
}
