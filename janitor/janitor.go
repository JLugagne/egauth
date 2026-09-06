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
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrInvalidInterval is returned by [New] when interval <= 0.
var ErrInvalidInterval = errors.New("janitor: interval must be positive")

// DefaultInterval is the fallback duration used by [Start] when interval <= 0.
const DefaultInterval = time.Minute

// Option configures a [Janitor].
type Option func(*options)

type options struct {
	panicHandler func(recovered any)
	errorHandler func(err error)
}

// WithPanicHandler registers a callback to be invoked if the cleanup task panics.
func WithPanicHandler(h func(recovered any)) Option {
	return func(o *options) {
		o.panicHandler = h
	}
}

// WithOnError registers an error callback to be invoked if the cleanup task panics or fails.
func WithOnError(h func(err error)) Option {
	return func(o *options) {
		o.errorHandler = h
	}
}

// Janitor manages a single background goroutine that periodically calls a cleanup
// function. Create one via [Start] or [New].
type Janitor struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// New creates and starts a background goroutine that calls fn every interval.
// It returns [ErrInvalidInterval] if interval <= 0.
func New(ctx context.Context, interval time.Duration, fn func(), opts ...Option) (*Janitor, error) {
	if interval <= 0 {
		return nil, ErrInvalidInterval
	}
	return start(ctx, interval, fn, opts...), nil
}

// Start launches a background goroutine that calls fn every interval. The goroutine
// stops when ctx is cancelled or when [Janitor.Stop] is called — whichever comes first.
// fn is called in the goroutine, not on the caller's goroutine; fn must be safe to call
// concurrently with other operations on the store it wraps.
//
// If interval <= 0, interval defaults to [DefaultInterval] (1 minute) to prevent busy loops.
func Start(ctx context.Context, interval time.Duration, fn func(), opts ...Option) *Janitor {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return start(ctx, interval, fn, opts...)
}

func start(ctx context.Context, interval time.Duration, fn func(), opts ...Option) *Janitor {
	var o options
	for _, opt := range opts {
		opt(&o)
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
				func() {
					defer func() {
						if r := recover(); r != nil {
							if o.panicHandler != nil {
								o.panicHandler(r)
							}
							if o.errorHandler != nil {
								if err, ok := r.(error); ok {
									o.errorHandler(err)
								} else {
									o.errorHandler(fmt.Errorf("janitor: panic: %v", r))
								}
							}
							if o.panicHandler == nil && o.errorHandler == nil {
								slog.Error("janitor: task panicked", "panic", r)
							}
						}
					}()
					fn()
				}()
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
