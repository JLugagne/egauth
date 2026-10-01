// Regression tests for F-OTP-001 and F-OTP-002.
//
// F-OTP-001: the issue cooldown must survive every terminal transition of the outstanding
// code — expiry, attempt exhaustion, the last wrong guess and a successful consume. Deleting
// the row must not delete the issuance state, or burn-then-reissue resets the attempt budget
// and makes online OTP brute force practical.
//
// F-OTP-002: issuance is one atomic store operation, so N concurrent issue requests cannot
// all pass the cooldown check and deliver N codes.
package otp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestService_CooldownSurvivesBurn covers the service-level bypass: after the code is burned
// by the last wrong guess, the very next Issue at the same instant must still be refused.
func TestService_CooldownSurvivesBurn(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now), otp.WithMaxAttempts(3))
	sub := uuid.Must(uuid.NewV7())

	ch1, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", wrongCode(ch1.Code)), otp.ErrInvalidCode)
	require.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", wrongCode(ch1.Code)), otp.ErrInvalidCode)
	require.ErrorIs(t, svc.Verify(ctx, "t1", sub, "login", wrongCode(ch1.Code)), otp.ErrTooManyAttempts)

	_, err = svc.Issue(ctx, "t1", sub, "login")
	require.ErrorIs(t, err, otp.ErrCooldownActive,
		"burning the code must not reset the issue cooldown")

	clk.t = clk.t.Add(otp.DefaultCooldown + time.Second)
	ch2, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.NotNil(t, ch2)
}

// TestService_CooldownSurvivesSuccessfulConsume covers the other terminal transition: a
// successful verification consumes the row, and the cooldown must still apply afterwards.
func TestService_CooldownSurvivesSuccessfulConsume(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now))
	sub := uuid.Must(uuid.NewV7())

	ch1, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.NoError(t, svc.Verify(ctx, "t1", sub, "login", ch1.Code))

	_, err = svc.Issue(ctx, "t1", sub, "login")
	require.ErrorIs(t, err, otp.ErrCooldownActive,
		"a successful consume must not reset the issue cooldown")
}

// TestService_CooldownSurvivesInvalidate covers explicit invalidation: the row is deleted but
// the issuance state must persist so the cooldown keeps applying.
func TestService_CooldownSurvivesInvalidate(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now))
	sub := uuid.Must(uuid.NewV7())

	_, err := svc.Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)
	require.NoError(t, svc.Invalidate(ctx, "t1", sub, "login"))

	_, err = svc.Issue(ctx, "t1", sub, "login")
	require.ErrorIs(t, err, otp.ErrCooldownActive,
		"invalidating the code must not reset the issue cooldown")
}

// TestService_ConcurrentIssue_YieldsExactlyOneSuccess is the F-OTP-002 invariant at the
// service level: atomic issuance lets exactly one of N concurrent requests through.
func TestService_ConcurrentIssue_YieldsExactlyOneSuccess(t *testing.T) {
	const n = 16
	ctx := context.Background()
	svc := otp.NewService(memory.NewStore())
	sub := uuid.Must(uuid.NewV7())

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		issued int
	)
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			if _, err := svc.Issue(ctx, "t1", sub, "login"); err == nil {
				mu.Lock()
				issued++
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()

	require.Equal(t, 1, issued,
		"concurrent issues must not all pass the cooldown check: exactly one may mint")
}

// TestIssueHandler_NoRedeliveryAfterBurnWithinCooldown is the end-to-end proof of F-OTP-001:
// after the code is burned, a reissue inside the cooldown window must not dispatch another
// delivery.
func TestIssueHandler_NoRedeliveryAfterBurnWithinCooldown(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := otp.NewService(memory.NewStore(), otp.WithClock(clk.now), otp.WithMaxAttempts(3))
	subject := uuid.Must(uuid.NewV7())

	var (
		mu         sync.Mutex
		deliveries []string
	)
	deliver := func(_ context.Context, ch *otp.Challenge) error {
		mu.Lock()
		deliveries = append(deliveries, ch.Code)
		mu.Unlock()
		return nil
	}
	resolver := otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return subject, true })
	issueH := otp.IssueHandler(svc, deliver, resolver)
	verifyH := otp.VerifyHandler(svc, resolver)

	deliveryCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(deliveries)
	}
	waitForDeliveries := func(want int) {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if deliveryCount() >= want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d delivery/deliveries (got %d)", want, deliveryCount())
	}

	rec := httptest.NewRecorder()
	issueH.ServeHTTP(rec, issuePost())
	require.Equal(t, http.StatusNoContent, rec.Code)
	waitForDeliveries(1)

	mu.Lock()
	firstCode := deliveries[0]
	mu.Unlock()

	for i := 0; i < 3; i++ {
		rec = httptest.NewRecorder()
		verifyH.ServeHTTP(rec, codeForm(wrongCode(firstCode)))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Same clock instant: the cooldown must still hold, so no second delivery lands.
	rec = httptest.NewRecorder()
	issueH.ServeHTTP(rec, issuePost())
	require.Equal(t, http.StatusNoContent, rec.Code, "the handler stays uniform")
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, deliveryCount(),
		"burn-then-reissue inside the cooldown must not dispatch a second OTP")
}

// TestIssueHandler_ConcurrentIssue_YieldsOneDelivery is the F-OTP-002 end-to-end invariant:
// N concurrent issue requests produce exactly one out-of-band delivery.
func TestIssueHandler_ConcurrentIssue_YieldsOneDelivery(t *testing.T) {
	const n = 8
	svc := otp.NewService(memory.NewStore())
	subject := uuid.Must(uuid.NewV7())

	var (
		mu         sync.Mutex
		deliveries int
	)
	deliver := func(context.Context, *otp.Challenge) error {
		mu.Lock()
		deliveries++
		mu.Unlock()
		return nil
	}
	h := otp.IssueHandler(svc, deliver, otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) {
		return subject, true
	}))

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, issuePost())
		})
	}
	close(start)
	wg.Wait()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		d := deliveries
		mu.Unlock()
		if d >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	got := deliveries
	mu.Unlock()
	require.Equal(t, 1, got,
		"concurrent issue requests must yield exactly one delivery inside the cooldown window")
}
