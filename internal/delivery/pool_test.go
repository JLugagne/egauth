package delivery_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/delivery"
	"github.com/JLugagne/egauth/internal/httpx"
)

type sink struct {
	mu  sync.Mutex
	got []event.Event
}

func (s *sink) EmitEvent(_ context.Context, e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
}

func (s *sink) failed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.got {
		if e.Type == event.DeliveryFailed {
			n++
		}
	}
	return n
}

func tenant(t *testing.T) core.TenantID {
	t.Helper()
	id, err := core.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCloseDrainsTheQueueBeforeReturning(t *testing.T) {
	s := &sink{}
	p := delivery.New(httpx.SinkAudit(s))
	var sent atomic.Int64
	for range delivery.QueueSize {
		p.Enqueue(context.Background(), tenant(t), uuid.New(), func(context.Context) error {
			sent.Add(1)
			return nil
		})
	}
	p.Close()
	if got := sent.Load() + int64(s.failed()); got != delivery.QueueSize {
		t.Fatalf("%d messages accounted for after Close, want %d delivered or reported", got, delivery.QueueSize)
	}
	if s.failed() != 0 {
		t.Fatalf("%d quick messages reported as failed", s.failed())
	}
}

func TestAMessageAfterCloseIsReported(t *testing.T) {
	s := &sink{}
	p := delivery.New(httpx.SinkAudit(s))
	p.Close()
	p.Close()
	p.Enqueue(context.Background(), tenant(t), uuid.New(), func(context.Context) error {
		t.Error("a message enqueued after Close was sent")
		return nil
	})
	if s.failed() != 1 {
		t.Fatalf("got %d delivery.failed events, want 1", s.failed())
	}
}
