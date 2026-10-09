package codesvc

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
	workerCount = 4
	queueSize   = 256
	jobTimeout  = 30 * time.Second
)

var (
	errQueueFull = errors.New("codesvc: delivery queue full")
	errClosed    = errors.New("codesvc: service closed")
)

type job struct {
	id     uuid.UUID
	tenant core.TenantID
	run    func(ctx context.Context, id uuid.UUID) error
	ctx    context.Context
}

type workers struct {
	audit  httpx.Audit
	mu     sync.RWMutex
	closed bool
	queue  chan job
	wg     sync.WaitGroup
}

func newWorkers(a httpx.Audit) *workers {
	w := &workers{audit: a, queue: make(chan job, queueSize)}
	w.wg.Add(workerCount)
	for range workerCount {
		go w.loop()
	}
	return w
}

func (w *workers) loop() {
	defer w.wg.Done()
	for j := range w.queue {
		ctx, cancel := context.WithTimeout(j.ctx, jobTimeout)
		err := j.run(ctx, j.id)
		cancel()
		if err != nil {
			w.failed(j, err)
		}
	}
}

func (w *workers) enqueue(ctx context.Context, t core.TenantID, run func(context.Context, uuid.UUID) error) {
	j := job{id: uuid.New(), tenant: t, run: run, ctx: context.WithoutCancel(ctx)}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.failed(j, errClosed)
		return
	}
	select {
	case w.queue <- j:
	default:
		w.failed(j, errQueueFull)
	}
}

func (w *workers) failed(j job, err error) {
	_ = w.audit.Emit(j.ctx, event.DeliveryFailed, audit.Scope{TenantID: j.tenant.String()},
		audit.Detail{Reason: "delivery_failed"}, err, audit.A(event.KeyDeliveryID, j.id.String()))
}

func (w *workers) close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()
	w.wg.Wait()
}
