package lifecycle_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
)

type memOutbox struct {
	mu      sync.Mutex
	rows    []identity.OutboxItem
	acked   []int64
	failed  map[int64]time.Time
	readErr error
}

func (o *memOutbox) PendingOutbox(context.Context, int) ([]identity.OutboxItem, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.readErr != nil {
		return nil, o.readErr
	}
	return append([]identity.OutboxItem(nil), o.rows...), nil
}

func (o *memOutbox) AckOutbox(_ context.Context, id int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.acked = append(o.acked, id)
	o.rows = slices.DeleteFunc(o.rows, func(r identity.OutboxItem) bool { return r.ID == id })
	return nil
}

func (o *memOutbox) FailOutbox(_ context.Context, id int64, next time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failed == nil {
		o.failed = map[int64]time.Time{}
	}
	o.failed[id] = next
	return nil
}

func (o *memOutbox) ackedIDs() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]int64(nil), o.acked...)
}

type dispatchCase struct {
	m     matrixCase
	out   *memOutbox
	rep   *retries
	clk   *clock.Test
	disp  *lifecycle.Dispatcher
	start time.Time
}

func newDispatchCase(t *testing.T) dispatchCase {
	t.Helper()
	m := newMatrixCase(t)
	start := clock.Clock{}.Now().UTC().Truncate(time.Second)
	d := dispatchCase{m: m, out: &memOutbox{}, rep: &retries{}, clk: clock.NewTest(start), start: start}
	disp, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: d.out, Wiring: m.world.wiring, Reporter: d.rep, Clock: d.clk.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	d.disp = disp
	return d
}

func (d dispatchCase) row(id int64, c identity.Component, e identity.Event) identity.OutboxItem {
	return identity.OutboxItem{
		ID: id, Component: c, Event: e, Subject: d.m.user.Subject, Keep: d.m.keep,
		Rotation: identity.RotationPasswordReset, Change: identity.FactorTOTPEnrolled, CreatedAt: d.start,
	}
}

func (d dispatchCase) rowsFor(e identity.Event) []identity.OutboxItem {
	var rows []identity.OutboxItem
	for _, c := range identity.Components() {
		rows = append(rows, d.row(int64(c), c, e))
	}
	return rows
}

func TestNewDispatcherRejectsIncompleteWiring(t *testing.T) {
	m := newMatrixCase(t)
	w := m.world.wiring
	w.MFA = nil
	_, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: &memOutbox{}, Wiring: w, Reporter: &retries{}})
	if !errors.Is(err, lifecycle.ErrInvalidWiring) || !strings.Contains(err.Error(), "mfa") {
		t.Fatalf("want ErrInvalidWiring naming mfa, got %v", err)
	}
	_, err = lifecycle.NewDispatcher(lifecycle.Config{Wiring: m.world.wiring})
	if !errors.Is(err, lifecycle.ErrInvalidWiring) {
		t.Fatalf("want ErrInvalidWiring for missing outbox and reporter, got %v", err)
	}
}

func TestFastPathAcksEveryRowAndRunsIdentityLast(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.take()
	d.disp.DispatchOutbox(context.Background(), d.rowsFor(identity.EventDelete))
	if got := len(d.out.ackedIDs()); got != len(identity.Components()) {
		t.Fatalf("want every row acked, got %d", got)
	}
	log := d.m.world.c.take()
	if last := log[len(log)-1]; !strings.HasPrefix(last, "identity.EraseUser") {
		t.Fatalf("identity hard delete must run last, got %v", log)
	}
	if len(d.rep.all()) != 0 {
		t.Fatalf("no retry expected, got %v", d.rep.all())
	}
}

func TestFailingSubscriberLeavesRetryableRowWhileOthersStillRun(t *testing.T) {
	d := newDispatchCase(t)
	boom := errors.New("ceremony store down")
	d.m.world.c.failOn("ceremony.", boom)
	d.m.world.c.take()
	d.disp.DispatchOutbox(context.Background(), d.rowsFor(identity.EventCredentialRotated))
	log := d.m.world.c.take()
	if !slices.ContainsFunc(log, func(s string) bool { return strings.HasPrefix(s, "backend.OnCredentialRotated") }) {
		t.Fatalf("sessions must still be killed by the epoch path, got %v", log)
	}
	mfaRow := int64(identity.ComponentCeremonies)
	if _, ok := d.out.failed[mfaRow]; !ok {
		t.Fatalf("the failing row must be deferred, failed=%v", d.out.failed)
	}
	if slices.Contains(d.out.ackedIDs(), mfaRow) {
		t.Fatal("the failing row must not be acknowledged")
	}
	if want := d.start.Add(lifecycle.RetryBase); !d.out.failed[mfaRow].Equal(want) {
		t.Fatalf("want first backoff %v, got %v", want, d.out.failed[mfaRow])
	}
	got := d.rep.all()
	if len(got) != 1 || got[0].Component != identity.ComponentCeremonies || got[0].Attempts != 1 || !errors.Is(got[0].Err, boom) {
		t.Fatalf("want one LifecycleRetry report for ceremonies, got %+v", got)
	}
}

func TestIdentityEraseWaitsQuietlyWhileOtherRowsPending(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("mfa.", errors.New("down"))
	d.m.world.c.failOn("identity.EraseUser", store.ErrConflict)
	d.disp.DispatchOutbox(context.Background(), d.rowsFor(identity.EventDelete))
	identityRow := int64(identity.ComponentIdentity)
	if slices.Contains(d.out.ackedIDs(), identityRow) {
		t.Fatal("identity row must not be acked while mfa is pending")
	}
	if _, ok := d.out.failed[identityRow]; !ok {
		t.Fatal("identity row must stay retryable")
	}
	for _, r := range d.rep.all() {
		if r.Component == identity.ComponentIdentity {
			t.Fatalf("a waiting identity row is not a failure to report: %+v", r)
		}
	}
}

func TestPanickingSubscriberIsRetriedNotPropagated(t *testing.T) {
	d := newDispatchCase(t)
	row := d.row(1, identity.ComponentHooks, identity.EventDelete)
	m := d.m
	hooks := lifecycle.NewHooks(func(context.Context, uuid.UUID, principal.Subject) error { panic("boom") }, m.world.hooks.tenantErased)
	w := m.world.wiring
	w.Hooks = hooks
	disp, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: d.out, Wiring: w, Reporter: d.rep, Clock: d.clk.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	disp.DispatchOutbox(context.Background(), []identity.OutboxItem{row})
	got := d.rep.all()
	if len(got) != 1 || !errors.Is(got[0].Err, lifecycle.ErrSubscriberPanic) {
		t.Fatalf("want a panic report, got %+v", got)
	}
}

func TestUndeclaredRowIsDeferredAsInvalid(t *testing.T) {
	d := newDispatchCase(t)
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{d.row(1, identity.Component(99), identity.EventDelete)})
	got := d.rep.all()
	if len(got) != 1 || !errors.Is(got[0].Err, lifecycle.ErrInvalidRow) {
		t.Fatalf("want ErrInvalidRow, got %+v", got)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	if lifecycle.Backoff(0) != lifecycle.RetryBase || lifecycle.Backoff(1) != 2*lifecycle.RetryBase {
		t.Fatal("backoff must start at RetryBase and double")
	}
	for _, n := range []int{20, 1000} {
		if lifecycle.Backoff(n) != lifecycle.RetryCap {
			t.Fatalf("attempt %d must be capped", n)
		}
	}
	if lifecycle.Backoff(-3) != lifecycle.RetryBase {
		t.Fatal("negative attempts must behave as zero")
	}
}

func TestRetrySkipsFreshUnattemptedRowsAndRunsOldOnes(t *testing.T) {
	d := newDispatchCase(t)
	fresh := d.row(1, identity.ComponentSessions, identity.EventDisable)
	attempted := d.row(2, identity.ComponentSessions, identity.EventDisable)
	attempted.Attempts = 1
	d.out.rows = []identity.OutboxItem{fresh, attempted}
	if err := d.disp.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.out.ackedIDs(); !slices.Equal(got, []int64{2}) {
		t.Fatalf("only the attempted row is due, acked %v", got)
	}
	d.clk.Advance(lifecycle.FastPathGrace + time.Second)
	if err := d.disp.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.out.ackedIDs(); !slices.Equal(got, []int64{2, 1}) {
		t.Fatalf("the orphaned row is picked up after the grace, acked %v", got)
	}
}

func TestRetryReportsUnreadableOutbox(t *testing.T) {
	d := newDispatchCase(t)
	d.out.readErr = errors.New("db down")
	err := d.disp.Retry(context.Background())
	if !errors.Is(err, lifecycle.ErrOutboxUnavailable) || !errors.Is(err, d.out.readErr) {
		t.Fatalf("got %v", err)
	}
}

func TestReadyFailsOnlyWhenAFailingRowIsOlderThanOneHour(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("mfa.", errors.New("down"))
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{d.row(4, identity.ComponentMFA, identity.EventDelete)})
	if err := d.disp.Ready(); err != nil {
		t.Fatalf("a young failing row is not stale: %v", err)
	}
	d.clk.Advance(lifecycle.StaleAfter + time.Second)
	if !errors.Is(d.disp.Ready(), lifecycle.ErrOutboxStale) {
		t.Fatal("a row failing for more than an hour must fail Ready")
	}
	d.m.world.c.failOn("mfa.", nil)
	d.out.rows = []identity.OutboxItem{func() identity.OutboxItem {
		r := d.row(4, identity.ComponentMFA, identity.EventDelete)
		r.Attempts = 1
		return r
	}()}
	if err := d.disp.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := d.disp.Ready(); err != nil {
		t.Fatalf("a delivered row must clear Ready: %v", err)
	}
}

func TestDispatchSurvivesCallerCancellation(t *testing.T) {
	d := newDispatchCase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.disp.DispatchOutbox(ctx, []identity.OutboxItem{d.row(1, identity.ComponentSessions, identity.EventDisable)})
	if !slices.Equal(d.out.ackedIDs(), []int64{1}) {
		t.Fatal("the committed mutation's rows are dispatched even if the request is cancelled")
	}
}

func TestEraseTenantTombstonesKeysFirstAndIdentityLast(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.take()
	if err := d.disp.EraseTenant(context.Background(), d.m.user.Subject.Tenant); err != nil {
		t.Fatal(err)
	}
	log := d.m.world.c.take()
	if !strings.HasPrefix(log[0], "keys.") || !strings.HasPrefix(log[len(log)-1], "identity.EraseTenant") {
		t.Fatalf("want keys first and identity last, got %v", log)
	}
}

func TestEraseTenantSkipsIdentityWhenAnotherComponentFailsAndKeepsDeliveryID(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("mfa.", errors.New("down"))
	if err := d.disp.EraseTenant(context.Background(), d.m.user.Subject.Tenant); err == nil {
		t.Fatal("want the failure joined")
	}
	if slices.ContainsFunc(d.m.world.c.take(), func(s string) bool { return strings.HasPrefix(s, "identity.EraseTenant") }) {
		t.Fatal("identity must not erase while another component failed")
	}
	d.m.world.c.failOn("mfa.", nil)
	if err := d.disp.EraseTenant(context.Background(), d.m.user.Subject.Tenant); err != nil {
		t.Fatal(err)
	}
	ids := d.m.world.hooks.deliveryIDs()
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("DeliveryID must be stable across retries, got %v", ids)
	}
}

func TestAccountDeletedHookDeliveryIDIsStable(t *testing.T) {
	d := newDispatchCase(t)
	row := d.row(1, identity.ComponentHooks, identity.EventDelete)
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{row})
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{row})
	ids := d.m.world.hooks.deliveryIDs()
	if len(ids) != 2 || ids[0] != ids[1] || ids[0] == uuid.Nil {
		t.Fatalf("got %v", ids)
	}
}

func TestEndSessionReachesTheBackendOnly(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.take()
	fam := uuid.New()
	if err := d.disp.EndSession(context.Background(), lifecycle.SessionEnded{Subject: d.m.user.Subject, Family: fam}); err != nil {
		t.Fatal(err)
	}
	log := d.m.world.c.take()
	if len(log) != 1 || log[0] != "backend.OnSessionEnded "+fam.String() {
		t.Fatalf("got %v", log)
	}
}

func TestRetryErrorWithoutCauseDoesNotPanic(t *testing.T) {
	if got := (lifecycle.Retry{Component: identity.ComponentMFA, Event: identity.EventDelete}).Error(); !strings.Contains(got, "deferred") {
		t.Fatalf("got %q", got)
	}
}

func TestWaitingIdentityRowBacksOffLikeAnyFailure(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("identity.EraseUser", store.ErrConflict)
	row := d.row(9, identity.ComponentIdentity, identity.EventDelete)
	row.Attempts = 4
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{row})
	if want := d.start.Add(lifecycle.Backoff(4)); !d.out.failed[9].Equal(want) {
		t.Fatalf("a waiting row must follow Backoff(attempts): want %v, got %v", want, d.out.failed[9])
	}
	if len(d.rep.all()) != 0 {
		t.Fatalf("a waiting row stays unreported, got %+v", d.rep.all())
	}
}

func TestReadySeesAStalePendingRowAfterARestart(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("mfa.", errors.New("down"))
	old := d.row(4, identity.ComponentMFA, identity.EventDelete)
	old.Attempts = 2
	old.CreatedAt = d.start.Add(-2 * lifecycle.StaleAfter)
	d.out.rows = []identity.OutboxItem{old}
	if err := d.disp.Ready(); err != nil {
		t.Fatalf("a fresh process has seen nothing: %v", err)
	}
	if err := d.disp.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(d.disp.Ready(), lifecycle.ErrOutboxStale) {
		t.Fatal("a row pending for more than an hour must fail Ready as soon as a pass sees it")
	}
}

func TestReadySeesAStaleRowEvenWhenThePassIsCancelled(t *testing.T) {
	d := newDispatchCase(t)
	old := d.row(4, identity.ComponentMFA, identity.EventDelete)
	old.Attempts = 2
	old.CreatedAt = d.start.Add(-2 * lifecycle.StaleAfter)
	d.out.rows = []identity.OutboxItem{old}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.disp.Retry(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(d.disp.Ready(), lifecycle.ErrOutboxStale) {
		t.Fatal("a stale pending row must be visible even if it was not run")
	}
}

func TestReadyForgetsRowsAnotherInstanceFinishedEvenWithAFullBatch(t *testing.T) {
	d := newDispatchCase(t)
	d.m.world.c.failOn("mfa.", errors.New("down"))
	d.disp.DispatchOutbox(context.Background(), []identity.OutboxItem{d.row(1000, identity.ComponentMFA, identity.EventDelete)})
	d.m.world.c.failOn("mfa.", nil)
	d.clk.Advance(2 * time.Minute)
	for i := 1; i <= lifecycle.RetryBatch; i++ {
		r := d.row(int64(i), identity.ComponentSessions, identity.EventDisable)
		r.Attempts = 1
		r.CreatedAt = d.start.Add(time.Duration(i) * time.Second)
		d.out.rows = append(d.out.rows, r)
	}
	if err := d.disp.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.clk.Advance(lifecycle.StaleAfter + time.Minute)
	if err := d.disp.Ready(); err != nil {
		t.Fatalf("row 1000 was finished elsewhere and older than the batch; Ready must have forgotten it: %v", err)
	}
}

type failingSessions struct{ fakeBackend }

func (failingSessions) OnCredentialRotated(context.Context, lifecycle.CredentialRotated) error {
	return errors.New("session backend down")
}

func TestFailingSessionSubscriberLeavesARetryableRowWhileTheEpochStillKillsSessions(t *testing.T) {
	m := newMatrixCase(t)
	clk := clock.NewTest(clock.Clock{}.Now().UTC().Truncate(time.Second))
	mem := identitymem.NewWithClock(clk.Clock())
	ctx := context.Background()
	created, err := mem.Apply(ctx, identity.CreateVerified{
		Tenant: m.user.Subject.Tenant, Email: m.user.Email, PHC: identity.NewPasswordHash("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := mem.CurrentEpoch(ctx, created.Subject)
	if err != nil {
		t.Fatal(err)
	}
	w := m.world.wiring
	w.Sessions, err = lifecycle.NewSessions(failingSessions{fakeBackend{c: m.world.c}})
	if err != nil {
		t.Fatal(err)
	}
	disp, err := lifecycle.NewDispatcher(lifecycle.Config{Outbox: mem, Wiring: w, Reporter: &retries{}, Clock: clk.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := mem.Apply(ctx, identity.SetPassword{
		Subject: created.Subject, PHC: identity.NewPasswordHash("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$bmV3"), Reason: identity.RotationPasswordReset,
	})
	if err != nil {
		t.Fatal(err)
	}
	disp.DispatchOutbox(ctx, applied.Outbox)
	after, err := mem.CurrentEpoch(ctx, created.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("the epoch must be bumped by the mutation itself: %d -> %d", before, after)
	}
	clk.Advance(lifecycle.RetryBase + time.Second)
	pending, err := mem.PendingOutbox(ctx, lifecycle.RetryBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Component != identity.ComponentSessions {
		t.Fatalf("only the failed sessions row must stay pending and retryable, got %+v", pending)
	}
}
