package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	// RetryBase is the delay before the first retry of a failed row; it doubles with every attempt.
	RetryBase = 5 * time.Second
	// RetryCap bounds the delay between two retries of a row.
	RetryCap = 5 * time.Minute
	// RetryBatch is how many due rows one Retry pass runs.
	RetryBatch = 100
	// FastPathGrace is how long Retry leaves a never-attempted row to the fast path of the
	// request that wrote it; a row whose writer crashed after commit is picked up after it.
	FastPathGrace = 30 * time.Second
	// StaleAfter is the age past which a row that is still not done makes Ready fail.
	StaleAfter  = time.Hour
	forgetSlack = time.Minute
)

var (
	// ErrOutboxStale is returned by Ready while a row seen failing is older than StaleAfter.
	ErrOutboxStale = errors.New("lifecycle: an outbox row has been pending for more than an hour")
	// ErrOutboxUnavailable is returned by Retry when the pending rows cannot be read.
	ErrOutboxUnavailable = errors.New("lifecycle: the outbox cannot be read")
)

// Backoff returns the delay before the next attempt of a row that already failed attempts times:
// RetryBase doubled per attempt, capped at RetryCap.
func Backoff(attempts int) time.Duration {
	d := RetryBase
	for range max(attempts, 0) {
		if d >= RetryCap/2 {
			return RetryCap
		}
		d *= 2
	}
	return min(d, RetryCap)
}

// Retry runs one bounded pass over the due rows, oldest first: at most RetryBatch rows, skipping
// rows still owned by the fast path (never attempted and younger than FastPathGrace) and rows this
// process is already running. It returns ErrOutboxUnavailable, joined with the store error, when
// the rows cannot be read; delivery failures are deferred and reported, not returned.
func (d *Dispatcher) Retry(ctx context.Context) error {
	items, err := d.outbox.PendingOutbox(ctx, RetryBatch)
	if err != nil {
		return errors.Join(ErrOutboxUnavailable, err)
	}
	now := d.clock.Now()
	seen := make(map[int64]bool, len(items))
	for _, it := range items {
		seen[it.ID] = true
		if now.Sub(createdAt(it, now)) > StaleAfter {
			d.watch(it, now)
		}
		if it.Attempts == 0 && now.Sub(createdAt(it, now)) < FastPathGrace {
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		d.process(ctx, it)
	}
	var horizon time.Time
	if len(items) >= RetryBatch {
		horizon = createdAt(items[len(items)-1], now)
	}
	d.forgetDone(seen, now, horizon)
	return nil
}

// Ready returns ErrOutboxStale while a row this process saw failing, or saw pending in a Retry pass
// after it was already older than StaleAfter, has not been seen done since.
func (d *Dispatcher) Ready() error {
	now := d.clock.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range d.failing {
		if now.Sub(t.created) > StaleAfter {
			return ErrOutboxStale
		}
	}
	return nil
}

func createdAt(it identity.OutboxItem, now time.Time) time.Time {
	if it.CreatedAt.IsZero() {
		return now
	}
	return it.CreatedAt
}

func (d *Dispatcher) claim(id int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, busy := d.inflight[id]; busy {
		return false
	}
	d.inflight[id] = struct{}{}
	return true
}

func (d *Dispatcher) release(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.inflight, id)
}

func (d *Dispatcher) track(it identity.OutboxItem, next time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.failing[it.ID]
	if !ok {
		t.created = createdAt(it, d.clock.Now())
	}
	t.next = next
	d.failing[it.ID] = t
}

func (d *Dispatcher) watch(it identity.OutboxItem, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.failing[it.ID]; !ok {
		d.failing[it.ID] = tracked{created: createdAt(it, now), next: now}
	}
}

func (d *Dispatcher) untrack(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.failing, id)
}

func (d *Dispatcher) forgetDone(seen map[int64]bool, now, horizon time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, t := range d.failing {
		beyondBatch := !horizon.IsZero() && !t.created.Before(horizon)
		if !seen[id] && !beyondBatch && t.next.Before(now.Add(-forgetSlack)) {
			delete(d.failing, id)
		}
	}
}

func (d *Dispatcher) process(ctx context.Context, it identity.OutboxItem) {
	if !d.claim(it.ID) {
		return
	}
	defer d.release(it.ID)
	err := d.deliver(ctx, it)
	book, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeeping)
	defer cancel()
	now := d.clock.Now()
	if err == nil {
		if aerr := d.outbox.AckOutbox(book, it.ID); aerr != nil {
			d.track(it, now)
			d.report(ctx, it, errors.Join(errors.New("lifecycle: acknowledging the row"), aerr))
			return
		}
		d.untrack(it.ID)
		return
	}
	waiting := it.Component == identity.ComponentIdentity && errors.Is(err, store.ErrConflict)
	next := now.Add(Backoff(it.Attempts))
	d.track(it, next)
	if ferr := d.outbox.FailOutbox(book, it.ID, next); ferr != nil {
		d.report(ctx, it, errors.Join(err, errors.New("lifecycle: deferring the row"), ferr))
		return
	}
	if !waiting {
		d.report(ctx, it, err)
	}
}

func (d *Dispatcher) report(ctx context.Context, it identity.OutboxItem, err error) {
	defer func() { _ = recover() }()
	d.reporter.ReportRetry(context.WithoutCancel(ctx), Retry{
		Component: it.Component,
		Event:     it.Event,
		Subject:   it.Subject,
		Attempts:  it.Attempts + 1,
		Err:       err,
	})
}
