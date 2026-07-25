package memory_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/JLugagne/egauth/otp/storetest"
	"github.com/google/uuid"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}

// TestBoundedOTPStore_NeverExceedsCap verifies that a bounded OTP store never
// holds more than maxSize codes. When the cap is reached the oldest code
// (by ExpiresAt) is evicted before the new one is inserted.
func TestBoundedOTPStore_NeverExceedsCap(t *testing.T) {
	ctx := context.Background()
	const cap = 3
	store := memory.NewBoundedStore(cap)
	future := time.Now().Add(time.Hour)

	for i := range cap {
		o := &otp.OTP{
			SubjectID: uuid.Must(uuid.NewV7()),
			Purpose:   "login",
			CodeHash:  "hash-" + strconv.Itoa(i),
			ExpiresAt: future.Add(time.Duration(i) * time.Second),
			CreatedAt: time.Now(),
		}
		if err := store.SaveOTP(ctx, "t1", o); err != nil {
			t.Fatalf("SaveOTP %d: %v", i, err)
		}
	}
	if got := store.Len(); got != cap {
		t.Fatalf("Len() after fill: got %d want %d", got, cap)
	}

	// Insert one more — must evict an existing entry to stay at cap.
	extra := &otp.OTP{
		SubjectID: uuid.Must(uuid.NewV7()),
		Purpose:   "login",
		CodeHash:  "hash-extra",
		ExpiresAt: future.Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := store.SaveOTP(ctx, "t1", extra); err != nil {
		t.Fatalf("SaveOTP extra: %v", err)
	}
	if got := store.Len(); got != cap {
		t.Fatalf("Len() after over-cap insert: got %d want %d", got, cap)
	}

	// The extra OTP must be retrievable.
	if _, err := store.GetOTP(ctx, "t1", extra.SubjectID, extra.Purpose); err != nil {
		t.Fatalf("GetOTP extra: %v", err)
	}
}

// TestBoundedOTPStore_EvictsExpiredFirst verifies that already-expired codes
// are evicted before live ones when the cap is reached.
func TestBoundedOTPStore_EvictsExpiredFirst(t *testing.T) {
	ctx := context.Background()
	const cap = 3
	store := memory.NewBoundedStore(cap)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)

	expiredSubject := uuid.Must(uuid.NewV7())
	liveSubject1 := uuid.Must(uuid.NewV7())
	liveSubject2 := uuid.Must(uuid.NewV7())

	entries := []*otp.OTP{
		{SubjectID: expiredSubject, Purpose: "p", CodeHash: "e", ExpiresAt: past, CreatedAt: time.Now()},
		{SubjectID: liveSubject1, Purpose: "p", CodeHash: "l1", ExpiresAt: future, CreatedAt: time.Now()},
		{SubjectID: liveSubject2, Purpose: "p", CodeHash: "l2", ExpiresAt: future.Add(time.Second), CreatedAt: time.Now()},
	}
	for _, e := range entries {
		if err := store.SaveOTP(ctx, "t1", e); err != nil {
			t.Fatalf("SaveOTP: %v", err)
		}
	}

	// 4th insertion — should evict the expired one.
	extraSubject := uuid.Must(uuid.NewV7())
	extra := &otp.OTP{
		SubjectID: extraSubject,
		Purpose:   "p",
		CodeHash:  "extra",
		ExpiresAt: future.Add(2 * time.Second),
		CreatedAt: time.Now(),
	}
	if err := store.SaveOTP(ctx, "t1", extra); err != nil {
		t.Fatalf("SaveOTP extra: %v", err)
	}
	if store.Len() != cap {
		t.Fatalf("Len() after eviction: got %d want %d", store.Len(), cap)
	}

	// Expired entry must be gone.
	if _, err := store.GetOTP(ctx, "t1", expiredSubject, "p"); !errors.Is(err, otp.ErrCodeNotFound) {
		t.Fatalf("expired OTP survived eviction: err=%v", err)
	}
	// Live entries must still be present.
	for _, subj := range []uuid.UUID{liveSubject1, liveSubject2, extraSubject} {
		if _, err := store.GetOTP(ctx, "t1", subj, "p"); err != nil {
			t.Fatalf("live OTP %v missing after eviction: %v", subj, err)
		}
	}
}

// TestNewOTPStore_Unbounded confirms the existing NewStore constructor is unbounded.
func TestNewOTPStore_Unbounded(t *testing.T) {
	store := memory.NewStore()
	// Verify it accepts many entries without eviction.
	ctx := context.Background()
	for i := range 100 {
		o := &otp.OTP{
			SubjectID: uuid.Must(uuid.NewV7()),
			Purpose:   "p",
			CodeHash:  "h" + strconv.Itoa(i),
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(),
		}
		if err := store.SaveOTP(ctx, "t1", o); err != nil {
			t.Fatalf("SaveOTP %d: %v", i, err)
		}
	}
	if got := store.Len(); got != 100 {
		t.Fatalf("Len() for unbounded store: got %d want 100", got)
	}
}
