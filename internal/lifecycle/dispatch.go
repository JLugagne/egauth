package lifecycle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	// DeliveryTimeout bounds one subscriber call.
	DeliveryTimeout = 10 * time.Second
	// FastPathBudget bounds the synchronous dispatch that follows a commit; rows it does not reach
	// stay due and are run by the reaper.
	FastPathBudget = 15 * time.Second
	bookkeeping    = 5 * time.Second
)

var (
	// ErrSubscriberPanic reports a subscriber that panicked; the row is retried like a failure.
	ErrSubscriberPanic = errors.New("lifecycle: subscriber panicked")
	// ErrInvalidRow reports an outbox row whose component or event is not declared.
	ErrInvalidRow = errors.New("lifecycle: outbox row has an undeclared component or event")
)

// Wiring is the row of every outbox component, built by the adapter constructors of this package.
// Each field is typed, so one component's adapter cannot be wired in another's place; a deployment
// without an optional store passes AbsentAPIKeys, AbsentFederation or AbsentKeys.
type Wiring struct {
	Sessions   *Sessions
	APIKeys    *APIKeys
	Ceremonies *Ceremonies
	MFA        *MFA
	Passkeys   *Passkeys
	Federation *Federation
	Notices    *Notices
	Keys       *Keys
	Hooks      *Hooks
	Identity   *Identity
}

func (w Wiring) adapters() []adapter {
	return []adapter{w.Sessions, w.APIKeys, w.Ceremonies, w.MFA, w.Passkeys, w.Federation, w.Notices, w.Keys, w.Hooks, w.Identity}
}

// Outbox is the part of identity.Store the dispatcher reads and acknowledges rows through.
type Outbox interface {
	PendingOutbox(ctx context.Context, limit int) ([]identity.OutboxItem, error)
	AckOutbox(ctx context.Context, id int64) error
	FailOutbox(ctx context.Context, id int64, next time.Time) error
}

// Retry describes one failed outbox delivery that was deferred. Attempts counts this failure.
type Retry struct {
	Component identity.Component
	Event     identity.Event
	Subject   principal.Subject
	Attempts  int
	Err       error
}

// Error implements error, so a Retry is itself the failure it describes.
func (r Retry) Error() string {
	msg := "lifecycle: " + r.Component.String() + "." + r.Event.String() + " deferred"
	if r.Err != nil {
		msg += ": " + r.Err.Error()
	}
	return msg
}

// Unwrap returns the delivery failure.
func (r Retry) Unwrap() error { return r.Err }

// RetryReporter is told of every deferred delivery, so that event.LifecycleRetry reaches the sink
// (reap.RetryEvents). It must not block.
type RetryReporter interface {
	ReportRetry(ctx context.Context, r Retry)
}

// Config is what NewDispatcher needs; every member is required. The zero Clock reads the wall
// clock; the composition root passes the library clock.
type Config struct {
	Outbox   Outbox
	Wiring   Wiring
	Reporter RetryReporter
	Clock    clock.Clock
}

// Dispatcher runs the lifecycle outbox: the synchronous fast path after commit (DispatchOutbox),
// the retries the reaper drives (Retry), tenant erasure and session ends. It is safe for
// concurrent use. A row is processed by one goroutine of the process at a time; subscribers are
// idempotent, so another instance processing the same row is harmless.
type Dispatcher struct {
	outbox   Outbox
	wiring   Wiring
	reporter RetryReporter
	clock    clock.Clock

	mu       sync.Mutex
	inflight map[int64]struct{}
	failing  map[int64]tracked
}

type tracked struct {
	created time.Time
	next    time.Time
}

// NewDispatcher validates cfg and returns a dispatcher. It returns ErrInvalidWiring, joined with
// every problem, for a missing member, an adapter not built by its constructor, or a row that
// differs from Golden (only an optional store may be absent).
func NewDispatcher(cfg Config) (*Dispatcher, error) {
	var errs []error
	if !present(cfg.Outbox) {
		errs = append(errs, errors.New("outbox is required"))
	}
	if !present(cfg.Reporter) {
		errs = append(errs, errors.New("retry reporter is required"))
	}
	for i, a := range cfg.Wiring.adapters() {
		c := identity.Components()[i]
		if !present(a) || !a.usable() {
			errs = append(errs, errors.New(c.String()+" subscriber is required"))
			continue
		}
		got := a.cells()
		if a.component() != c || !accepts(c, got) {
			errs = append(errs, errors.New(c.String()+" subscriber does not match the lifecycle matrix"))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidWiring, errors.Join(errs...))
	}
	return &Dispatcher{
		outbox:   cfg.Outbox,
		wiring:   cfg.Wiring,
		reporter: cfg.Reporter,
		clock:    cfg.Clock,
		inflight: map[int64]struct{}{},
		failing:  map[int64]tracked{},
	}, nil
}

// Matrix returns the cells the wired adapters perform, per component: the introspection hook of
// the G18 golden wiring test. A cell reflects the dependency actually wired: an application hook
// left nil reports CellNone, an absent optional store CellAbsent.
func (d *Dispatcher) Matrix() map[identity.Component]Cells {
	out := make(map[identity.Component]Cells, len(identity.Components()))
	for _, a := range d.wiring.adapters() {
		out[a.component()] = a.cells()
	}
	return out
}

// Wired returns the object each component acts on: the session backend, or the store of the
// ceremony, MFA, passkey, federation, API-key, key and identity rows, nil for an absent optional
// store and for the notice and hook rows, which hold functions (their presence shows in Matrix).
// G18 compares them with the objects the composed Auth owns, so a Dispatcher wired to a stand-in
// is caught.
func (d *Dispatcher) Wired() map[identity.Component]any {
	out := make(map[identity.Component]any, len(identity.Components()))
	for _, a := range d.wiring.adapters() {
		out[a.component()] = a.dependency()
	}
	return out
}

// DispatchOutbox is the fast path: it runs items, the rows an applied mutation wrote, in order
// (ComponentIdentity last) within FastPathBudget, acknowledging each success and deferring each
// failure with backoff. It reports nothing to the caller: the mutation has committed, so the
// operation has succeeded, and undone rows are retried by the reaper (DESIGN §7.1). The caller's
// cancellation does not stop it.
func (d *Dispatcher) DispatchOutbox(ctx context.Context, items []identity.OutboxItem) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), FastPathBudget)
	defer cancel()
	for _, it := range items {
		if ctx.Err() != nil {
			return
		}
		d.process(ctx, it)
	}
}

// EraseTenant runs TenantErased on every component: keys first, so the tenant is tombstoned before
// anything else is erased (T-13), the identity store last and only once every other component
// succeeded. It returns every failure joined; every step is idempotent, so the caller retries the
// whole call, and Hooks.TenantErased sees the same DeliveryID.
func (d *Dispatcher) EraseTenant(ctx context.Context, t principal.TenantID) error {
	e := TenantErased{Tenant: t}
	w := d.wiring
	order := []adapter{w.Keys, w.Sessions, w.APIKeys, w.Ceremonies, w.MFA, w.Passkeys, w.Federation, w.Notices, w.Hooks}
	var errs []error
	for _, a := range order {
		if err := d.call(ctx, a.component(), func(ctx context.Context) error { return a.forRow(identity.OutboxItem{}).OnTenantErased(ctx, e) }); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return d.call(ctx, identity.ComponentIdentity, func(ctx context.Context) error { return w.Identity.OnTenantErased(ctx, e) })
}

// EndSession runs SessionEnded on every component; only the session backend acts on it. It returns
// every failure joined.
func (d *Dispatcher) EndSession(ctx context.Context, e SessionEnded) error {
	var errs []error
	for _, a := range d.wiring.adapters() {
		if err := d.call(ctx, a.component(), func(ctx context.Context) error { return a.forRow(identity.OutboxItem{}).OnSessionEnded(ctx, e) }); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (d *Dispatcher) route(c identity.Component) (adapter, bool) {
	for _, a := range d.wiring.adapters() {
		if a.component() == c {
			return a, true
		}
	}
	return nil, false
}

func (d *Dispatcher) call(ctx context.Context, c identity.Component, f func(context.Context) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = errors.Join(ErrSubscriberPanic, errors.New(c.String()))
		}
	}()
	if err := f(ctx); err != nil {
		return errors.Join(errors.New("lifecycle: "+c.String()), err)
	}
	return nil
}

func (d *Dispatcher) deliver(ctx context.Context, item identity.OutboxItem) error {
	a, ok := d.route(item.Component)
	if !ok {
		return ErrInvalidRow
	}
	sub := a.forRow(item)
	account := AccountEvent{Subject: item.Subject}
	var f func(context.Context) error
	switch item.Event {
	case identity.EventCredentialRotated:
		e := CredentialRotated{Subject: item.Subject, Keep: item.Keep, Reason: RotationReason(item.Rotation)}
		f = func(ctx context.Context) error { return sub.OnCredentialRotated(ctx, e) }
	case identity.EventFactorsChanged:
		e := FactorsChanged{Subject: item.Subject, Keep: item.Keep, Change: FactorChange(item.Change)}
		f = func(ctx context.Context) error { return sub.OnFactorsChanged(ctx, e) }
	case identity.EventIdentifierChanged:
		e := IdentifierChanged{Subject: item.Subject, Kind: IdentifierKind(item.Identifier), Old: item.Old.Value()}
		f = func(ctx context.Context) error { return sub.OnIdentifierChanged(ctx, e) }
	case identity.EventDisable:
		f = func(ctx context.Context) error { return sub.OnDisabled(ctx, account) }
	case identity.EventEnable:
		f = func(ctx context.Context) error { return sub.OnEnabled(ctx, account) }
	case identity.EventDelete:
		f = func(ctx context.Context) error { return sub.OnDeleted(ctx, account) }
	default:
		return ErrInvalidRow
	}
	return d.call(ctx, item.Component, f)
}
