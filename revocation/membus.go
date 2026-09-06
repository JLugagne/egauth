package revocation

import (
	"context"
	"errors"
	"sync"
)

// MemBus is the zero-dependency, in-process Bus. Subscriptions are held per TargetType in memory
// and Publish fans a revocation out synchronously to the matching subscribers plus any wildcard
// (TargetAll) subscribers. It is safe for concurrent use.
//
// Being in-process, a MemBus only reaches subscribers registered on the same instance — it is the
// right default for single-binary deployments and tests. A deployment that revokes across
// processes substitutes a distributed Bus implementation; producers and subscribers are unaffected
// because they depend only on the Bus and Handler interfaces.
type MemBus struct {
	mu   sync.RWMutex
	subs map[TargetType][]Handler
}

// NewMemBus returns an empty, ready-to-use in-process Bus.
func NewMemBus() *MemBus {
	return &MemBus{subs: make(map[TargetType][]Handler)}
}

// Subscribe registers h to receive every revocation whose TargetType matches target. Subscribing
// with TargetAll registers a wildcard handler that receives every revocation. Handlers are
// invoked in subscription order.
func (b *MemBus) Subscribe(target TargetType, h Handler) {
	if h == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[target] = append(b.subs[target], h)
}

// Publish dispatches rev to the handlers subscribed to rev.TargetType and to any wildcard
// (TargetAll) handlers, in subscription order. It returns early with the context error if ctx is
// already cancelled, and otherwise calls every matched handler even if earlier ones fail,
// returning all handler errors joined via errors.Join (nil when every handler succeeds). The
// wildcard set is not double-delivered when rev.TargetType is itself TargetAll.
func (b *MemBus) Publish(ctx context.Context, rev Revocation) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.RLock()
	matched := make([]Handler, 0, len(b.subs[rev.TargetType])+len(b.subs[TargetAll]))
	matched = append(matched, b.subs[rev.TargetType]...)
	if rev.TargetType != TargetAll {
		matched = append(matched, b.subs[TargetAll]...)
	}
	b.mu.RUnlock()

	var errs []error
	for _, h := range matched {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if err := h.HandleRevocation(ctx, rev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
