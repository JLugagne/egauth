package memory

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChallengeStore_PutWorkIsBounded pins conc/AVAIL-1 (and tenant/TEN-7, mfa/SF-5): Put is
// driven by the UNAUTHENTICATED BeginRegistration / BeginLogin endpoints, so the work it does per
// call must not grow with the number of live entries. A sweep of the whole map on every insertion
// is linear in the live set — quadratic overall — and hands an anonymous caller a cheap way to
// make every ceremony slower under one global mutex.
func TestChallengeStore_PutWorkIsBounded(t *testing.T) {
	ctx := context.Background()
	cs := NewChallengeStore()
	expiry := time.Now().Add(time.Hour)

	const live = 20000
	for i := range live {
		require.NoError(t, cs.Put(ctx, "t1", "chal-"+strconv.Itoa(i), expiry))
	}

	cs.mu.Lock()
	before := cs.scanned
	cs.mu.Unlock()

	const extra = 100
	for i := range extra {
		require.NoError(t, cs.Put(ctx, "t1", "late-"+strconv.Itoa(i), expiry))
	}

	cs.mu.Lock()
	steps := cs.scanned - before
	cs.mu.Unlock()

	assert.LessOrEqual(t, steps, uint64(extra*maxPruneStepsPerPut),
		"Put must do a bounded amount of expiry work, not a full sweep of the %d live entries", live)
}

// TestChallengeStore_EntriesAreCapped pins the second half of the same finding: an anonymous
// caller must not be able to grow the store without bound.
func TestChallengeStore_EntriesAreCapped(t *testing.T) {
	ctx := context.Background()
	cs := NewChallengeStore(WithMaxEntries(100))
	expiry := time.Now().Add(time.Hour)

	for i := range 1000 {
		require.NoError(t, cs.Put(ctx, "t1", "chal-"+strconv.Itoa(i), expiry))
	}

	cs.mu.Lock()
	size := len(cs.entries)
	cs.mu.Unlock()
	assert.LessOrEqual(t, size, 100, "the live set must stay under the configured cap")

	// The eviction policy is oldest-first, so the most recent challenge is still consumable and the
	// oldest is gone.
	ok, err := cs.Consume(ctx, "t1", "chal-999")
	require.NoError(t, err)
	assert.True(t, ok, "the newest challenge must survive eviction")

	ok, err = cs.Consume(ctx, "t1", "chal-0")
	require.NoError(t, err)
	assert.False(t, ok, "the oldest challenge is the one evicted when the cap is reached")
}

// TestChallengeStore_QueueDoesNotGrowWithPeak pins that a traffic burst leaves no permanent
// bookkeeping behind once the entries it created are consumed.
func TestChallengeStore_QueueDoesNotGrowWithPeak(t *testing.T) {
	ctx := context.Background()
	cs := NewChallengeStore()
	expiry := time.Now().Add(time.Hour)

	const burst = 20000
	for i := range burst {
		require.NoError(t, cs.Put(ctx, "t1", "burst-"+strconv.Itoa(i), expiry))
	}
	for i := range burst {
		_, err := cs.Consume(ctx, "t1", "burst-"+strconv.Itoa(i))
		require.NoError(t, err)
	}
	for i := range 2 * burst {
		require.NoError(t, cs.Put(ctx, "t1", "after-"+strconv.Itoa(i), expiry))
	}

	cs.mu.Lock()
	pending := len(cs.queue) - cs.head
	cs.mu.Unlock()
	assert.LessOrEqual(t, pending, 2*burst+maxPruneStepsPerPut,
		"the expiry bookkeeping must track the live set, not the peak")
}

// TestChallengeStore_ExpiredEntriesAreReclaimed pins that the amortised prune still frees memory:
// entries that expired and were never consumed must not accumulate for ever.
func TestChallengeStore_ExpiredEntriesAreReclaimed(t *testing.T) {
	ctx := context.Background()
	cs := NewChallengeStore()

	past := time.Now().Add(-time.Second)
	for i := range 1000 {
		require.NoError(t, cs.Put(ctx, "t1", "old-"+strconv.Itoa(i), past))
	}
	future := time.Now().Add(time.Hour)
	for i := range 1000 {
		require.NoError(t, cs.Put(ctx, "t1", "new-"+strconv.Itoa(i), future))
	}

	cs.mu.Lock()
	size := len(cs.entries)
	cs.mu.Unlock()
	assert.LessOrEqual(t, size, 1000+maxPruneStepsPerPut,
		"expired entries must be reclaimed by the amortised prune")
}
