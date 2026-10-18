// Package delivery runs the outbound messages of the auth services (emails, texts) off the request
// path, on a fixed set of workers, and reports every message it could not deliver as
// event.DeliveryFailed.
package delivery

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
)

const (
	// Workers is the number of messages a Pool delivers at once.
	Workers = 4
	// QueueSize is the number of messages a Pool holds; Enqueue drops past it.
	QueueSize = 256
	// Timeout bounds one delivery.
	Timeout = 30 * time.Second
	// CloseGrace is how long Close lets the queue drain before it cancels the running deliveries
	// and drops the queued ones.
	CloseGrace = 5 * time.Second
	// AbortWait is how long Close then waits for deliverers to return; one that ignores its
	// context is abandoned.
	AbortWait = 2 * time.Second
)

var (
	// ErrQueueFull reports a message dropped because QueueSize messages were waiting.
	ErrQueueFull = errors.New("delivery: queue full")
	// ErrClosed reports a message enqueued after Close.
	ErrClosed = errors.New("delivery: closed")
	// ErrAborted reports a message still queued, or still running, when CloseGrace ran out.
	ErrAborted = errors.New("delivery: aborted by Close")
)

type job struct {
	id     uuid.UUID
	tenant core.TenantID
	send   func(context.Context) error
	ctx    context.Context
}

// Pool delivers messages on Workers goroutines. It is safe for concurrent use; Close is
// idempotent and returns within CloseGrace plus AbortWait.
type Pool struct {
	audit  httpx.Audit
	mu     sync.RWMutex
	closed bool
	queue  chan job
	wg     sync.WaitGroup
	abort  context.Context
	cancel context.CancelFunc
	once   sync.Once
}

// New starts a Pool reporting failures to a.
func New(a httpx.Audit) *Pool {
	abort, cancel := context.WithCancel(context.Background())
	p := &Pool{audit: a, queue: make(chan job, QueueSize), abort: abort, cancel: cancel}
	p.wg.Add(Workers)
	for range Workers {
		go p.work()
	}
	return p
}

// Enqueue queues send under the delivery id and returns at once. send runs with a context that
// keeps the values of ctx but not its cancellation, bounded by Timeout and cancelled by Close. A
// message that is dropped or fails is reported as event.DeliveryFailed.
func (p *Pool) Enqueue(ctx context.Context, t core.TenantID, id uuid.UUID, send func(context.Context) error) {
	j := job{id: id, tenant: t, send: send, ctx: context.WithoutCancel(ctx)}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.failed(j, ErrClosed)
		return
	}
	select {
	case p.queue <- j:
	default:
		p.failed(j, ErrQueueFull)
	}
}

// Close stops accepting messages, lets the queue drain for CloseGrace, then cancels what still runs
// and reports what is left as ErrAborted.
func (p *Pool) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.queue)
		p.mu.Unlock()
		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			p.cancel()
			return
		case <-time.After(CloseGrace):
		}
		p.cancel()
		select {
		case <-done:
		case <-time.After(AbortWait):
		}
	})
}

func (p *Pool) work() {
	defer p.wg.Done()
	for j := range p.queue {
		if p.abort.Err() != nil {
			p.failed(j, ErrAborted)
			continue
		}
		ctx, cancel := context.WithTimeout(j.ctx, Timeout)
		stop := context.AfterFunc(p.abort, cancel)
		err := j.send(ctx)
		stop()
		cancel()
		switch {
		case err != nil && p.abort.Err() != nil:
			p.failed(j, errors.Join(ErrAborted, err))
		case err != nil:
			p.failed(j, err)
		}
	}
}

func (p *Pool) failed(j job, err error) {
	_ = p.audit.Emit(j.ctx, event.DeliveryFailed, audit.Scope{TenantID: j.tenant.String()},
		audit.Detail{Reason: "delivery_failed"}, err, audit.A(event.KeyDeliveryID, j.id.String()))
}
