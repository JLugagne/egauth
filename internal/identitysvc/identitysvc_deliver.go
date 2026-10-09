package identitysvc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	deliveryWorkers = 4
	deliveryQueue   = 256
	deliveryTimeout = 30 * time.Second
)

var (
	errQueueFull = errors.New("identitysvc: delivery queue full")
	errClosed    = errors.New("identitysvc: service closed")
)

type delivery struct {
	id     uuid.UUID
	tenant core.TenantID
	send   func(ctx context.Context) error
	ctx    context.Context
}

type deliveries struct {
	mailer Mailer
	audit  httpx.Audit
	mu     sync.RWMutex
	closed bool
	queue  chan delivery
	wg     sync.WaitGroup
}

func newDeliveries(m Mailer, a httpx.Audit) *deliveries {
	d := &deliveries{mailer: m, audit: a, queue: make(chan delivery, deliveryQueue)}
	d.wg.Add(deliveryWorkers)
	for range deliveryWorkers {
		go d.work()
	}
	return d
}

func (d *deliveries) work() {
	defer d.wg.Done()
	for job := range d.queue {
		ctx, cancel := context.WithTimeout(job.ctx, deliveryTimeout)
		err := job.send(ctx)
		cancel()
		if err != nil {
			d.failed(job, err)
		}
	}
}

func (d *deliveries) enqueue(ctx context.Context, t core.TenantID, id uuid.UUID, send func(context.Context) error) {
	job := delivery{id: id, tenant: t, send: send, ctx: context.WithoutCancel(ctx)}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		d.failed(job, errClosed)
		return
	}
	select {
	case d.queue <- job:
	default:
		d.failed(job, errQueueFull)
	}
}

func (d *deliveries) failed(job delivery, err error) {
	_ = d.audit.Emit(job.ctx, event.DeliveryFailed, audit.Scope{TenantID: job.tenant.String()},
		audit.Detail{Reason: "delivery_failed"}, err, audit.A(event.KeyDeliveryID, job.id.String()))
}

func (d *deliveries) close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	d.wg.Wait()
}

func (s *Service) sendRegistrationLink(ctx context.Context, m LinkMessage) {
	m.DeliveryID = uuid.New()
	s.mail.enqueue(ctx, m.Tenant, m.DeliveryID, func(c context.Context) error {
		return s.mail.mailer.RegistrationLink(c, m)
	})
}

func (s *Service) sendAccountExists(ctx context.Context, m NoticeMessage) {
	m.DeliveryID = uuid.New()
	s.mail.enqueue(ctx, m.Tenant, m.DeliveryID, func(c context.Context) error {
		return s.mail.mailer.AccountExistsNotice(c, m)
	})
}

func (s *Service) sendReset(ctx context.Context, p core.Pending, u identity.User, st core.AccountState) {
	if s.noReset {
		return
	}
	id := uuid.New()
	s.mail.enqueue(ctx, u.Subject.Tenant, id, func(c context.Context) error {
		m, err := s.putReset(c, p, u, st)
		if err != nil {
			_ = s.audit.Emit(c, event.DeliveryFailed, scopeOf(u.Subject), audit.Detail{Reason: "password_reset"}, err,
				audit.A(event.KeyDeliveryID, id.String()))
			return nil
		}
		m.DeliveryID = id
		return s.mail.mailer.PasswordResetLink(c, m)
	})
}
