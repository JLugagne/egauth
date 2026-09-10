package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/mfa/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}

// TestNewStore_BoundedByDefault confirms NewStore caps recovery-attempt records by
// DefaultMaxEntries and that NewUnboundedStore is the explicitly named opt-out.
func TestNewStore_BoundedByDefault(t *testing.T) {
	if got := memory.NewStore().MaxEntries(); got != memory.DefaultMaxEntries {
		t.Fatalf("NewStore MaxEntries: got %d want %d (bounded default)", got, memory.DefaultMaxEntries)
	}
	if got := memory.NewUnboundedStore().MaxEntries(); got != 0 {
		t.Fatalf("NewUnboundedStore MaxEntries: got %d want 0 (unbounded)", got)
	}
}

// TestRecoveryAttemptsCapEnforcedAndUnboundedNotCapped proves a bounded store evicts the stalest
// recovery-attempt record when a new user is tracked at the cap, while the unbounded store keeps
// every record.
func TestRecoveryAttemptsCapEnforcedAndUnboundedNotCapped(t *testing.T) {
	ctx := context.Background()
	const tenant = "t1"
	base := time.Now()

	oldest := uuid.Must(uuid.NewV7())
	middle := uuid.Must(uuid.NewV7())
	newest := uuid.Must(uuid.NewV7())

	// Bounded at two records: tracking `newest` evicts the stalest record (`oldest`).
	bounded := memory.NewBoundedStore(2)
	for i, user := range []uuid.UUID{oldest, middle, newest} {
		if n, err := bounded.IncrementRecoveryAttempts(ctx, tenant, user, base.Add(time.Duration(i)*time.Second), 0, 0); err != nil || n != 1 {
			t.Fatalf("IncrementRecoveryAttempts(%d): n=%d err=%v", i, n, err)
		}
	}
	if n, _ := bounded.IncrementRecoveryAttempts(ctx, tenant, middle, base.Add(3*time.Second), 0, 0); n != 2 {
		t.Fatalf("surviving record: got attempts %d want 2", n)
	}
	if n, _ := bounded.IncrementRecoveryAttempts(ctx, tenant, newest, base.Add(4*time.Second), 0, 0); n != 2 {
		t.Fatalf("surviving newest record: got attempts %d want 2", n)
	}
	if n, _ := bounded.IncrementRecoveryAttempts(ctx, tenant, oldest, base.Add(5*time.Second), 0, 0); n != 1 {
		t.Fatalf("evicted oldest record: got attempts %d want 1 (fresh record)", n)
	}

	// Unbounded: every record survives, so the oldest accumulates attempts.
	unbounded := memory.NewUnboundedStore()
	for i, user := range []uuid.UUID{oldest, middle, newest} {
		if _, err := unbounded.IncrementRecoveryAttempts(ctx, tenant, user, base.Add(time.Duration(i)*time.Second), 0, 0); err != nil {
			t.Fatalf("IncrementRecoveryAttempts(%d): %v", i, err)
		}
	}
	if n, _ := unbounded.IncrementRecoveryAttempts(ctx, tenant, oldest, base.Add(time.Minute), 0, 0); n != 2 {
		t.Fatalf("unbounded store: got attempts %d want 2 (record must not be evicted)", n)
	}
}

// TestUnboundedStore_DeleteStaleRecoveryAttempts proves the schedulable reaper removes only the
// records older than the cutoff within the requested tenant.
func TestUnboundedStore_DeleteStaleRecoveryAttempts(t *testing.T) {
	ctx := context.Background()
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
	)
	base := time.Now()
	stale := uuid.Must(uuid.NewV7())
	fresh := uuid.Must(uuid.NewV7())
	otherTenant := uuid.Must(uuid.NewV7())

	store := memory.NewUnboundedStore()
	for _, tc := range []struct {
		tenant string
		user   uuid.UUID
		at     time.Time
	}{
		{tenantA, stale, base},
		{tenantA, fresh, base.Add(time.Hour)},
		{tenantB, otherTenant, base},
	} {
		if _, err := store.IncrementRecoveryAttempts(ctx, tc.tenant, tc.user, tc.at, 0, 0); err != nil {
			t.Fatalf("IncrementRecoveryAttempts(%s): %v", tc.user, err)
		}
	}

	deleted, err := store.DeleteStaleRecoveryAttempts(ctx, tenantA, base.Add(30*time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)

	if n, _ := store.IncrementRecoveryAttempts(ctx, tenantA, stale, base.Add(2*time.Hour), 0, 0); n != 1 {
		t.Fatalf("stale record must have been reaped: got attempts %d want 1", n)
	}
	if n, _ := store.IncrementRecoveryAttempts(ctx, tenantA, fresh, base.Add(3*time.Hour), 0, 0); n != 2 {
		t.Fatalf("fresh record must survive: got attempts %d want 2", n)
	}
	if n, _ := store.IncrementRecoveryAttempts(ctx, tenantB, otherTenant, base.Add(4*time.Hour), 0, 0); n != 2 {
		t.Fatalf("other tenant's record must survive: got attempts %d want 2", n)
	}
}
