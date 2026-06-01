package otp_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestService_ConcurrentVerify_SingleUse asserts that when many goroutines redeem the SAME
// correct code at once, exactly one succeeds (no double-spend / replay).
func TestService_ConcurrentVerify_SingleUse(t *testing.T) {
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(100))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)

	const n = 64
	var successes int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if svc.Verify(ctx, "t1", sub, "login", ch.Code) == nil {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), successes, "a single OTP must be redeemable exactly once, even under concurrency")
}

// TestService_ConcurrentVerify_AttemptLimit asserts that concurrent WRONG guesses cannot run
// more code comparisons than maxAttempts (the attempt ceiling holds under parallelism).
func TestService_ConcurrentVerify_AttemptLimit(t *testing.T) {
	ctx := context.Background()
	const maxAttempts = 5
	svc := otp.NewService(memory.NewStore(), otp.WithMaxAttempts(maxAttempts))
	sub := uuid.New()

	ch, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	bad := wrongCode(ch.Code)

	const n = 50
	var invalid int64 // ErrInvalidCode == a comparison was actually performed and failed
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := svc.Verify(ctx, "t1", sub, "login", bad); err == otp.ErrInvalidCode {
				atomic.AddInt64(&invalid, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// Only guesses within the limit reach compareCode; the rest are rejected as
	// ErrTooManyAttempts without a comparison. So the number of evaluated guesses is bounded.
	assert.LessOrEqual(t, invalid, int64(maxAttempts), "concurrent wrong guesses must not exceed the attempt ceiling")

	// And the code is burned afterwards.
	assert.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", ch.Code), otp.ErrCodeNotFound)
}
