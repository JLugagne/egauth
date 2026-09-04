package memory

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	store := NewStore()
	storetest.StoreContractTesting(t, store, true)
}

// newSession is a test helper building a session for tenantID with the given token hash.
func newSession(tenantID, tokenHash string, expiresAt time.Time) *sessions.Session {
	return &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  tenantID,
		UserID:    uuid.Must(uuid.NewV7()),
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// TestIndexConsistency proves the secondary hash index stays in lockstep with the
// primary map across create, find, update (rotation), delete and tenant isolation.
func TestIndexConsistency(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	future := time.Now().Add(time.Hour)

	// Create many sessions to ensure lookups don't depend on iteration.
	var created []*sessions.Session
	for i := range 1000 {
		sess := newSession("tenantA", "hash-"+strconv.Itoa(i), future)
		if err := store.CreateSession(ctx, "tenantA", sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		created = append(created, sess)
	}

	if len(store.sessions) != len(store.byHash) {
		t.Fatalf("index drift after create: sessions=%d byHash=%d", len(store.sessions), len(store.byHash))
	}

	// Each known hash resolves to the right session.
	target := created[500]
	got, err := store.FindSessionByHash(ctx, "tenantA", target.TokenHash)
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got.ID != target.ID {
		t.Fatalf("wrong session: got %v want %v", got.ID, target.ID)
	}

	// Absent hash returns not found.
	if _, err := store.FindSessionByHash(ctx, "tenantA", "no-such-hash"); err != sessions.ErrSessionNotFound {
		t.Fatalf("absent hash: got %v want ErrSessionNotFound", err)
	}

	// Tenant mismatch returns not found even though the hash exists.
	if _, err := store.FindSessionByHash(ctx, "tenantB", target.TokenHash); err != sessions.ErrSessionNotFound {
		t.Fatalf("tenant mismatch: got %v want ErrSessionNotFound", err)
	}

	// Rotation: update the token hash via compare-and-set; old hash must vanish, new resolves.
	rotated := *target
	rotated.TokenHash = "rotated-hash"
	if err := store.UpdateSession(ctx, "tenantA", &rotated, target.TokenHash); err != nil {
		t.Fatalf("UpdateSession rotation: %v", err)
	}
	if _, err := store.FindSessionByHash(ctx, "tenantA", target.TokenHash); err != sessions.ErrSessionNotFound {
		t.Fatalf("old hash after rotation: got %v want ErrSessionNotFound", err)
	}
	got, err = store.FindSessionByHash(ctx, "tenantA", "rotated-hash")
	if err != nil {
		t.Fatalf("new hash after rotation: %v", err)
	}
	if got.ID != target.ID {
		t.Fatalf("rotated lookup wrong session: got %v want %v", got.ID, target.ID)
	}
	if len(store.sessions) != len(store.byHash) {
		t.Fatalf("index drift after rotation: sessions=%d byHash=%d", len(store.sessions), len(store.byHash))
	}

	// Delete: the hash is gone afterwards.
	if err := store.DeleteSession(ctx, "tenantA", target.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := store.FindSessionByHash(ctx, "tenantA", "rotated-hash"); err != sessions.ErrSessionNotFound {
		t.Fatalf("hash after delete: got %v want ErrSessionNotFound", err)
	}
	if len(store.sessions) != len(store.byHash) {
		t.Fatalf("index drift after delete: sessions=%d byHash=%d", len(store.sessions), len(store.byHash))
	}

	// DeleteSessionsByUserID also clears the hash index.
	victim := created[1]
	if err := store.DeleteSessionsByUserID(ctx, "tenantA", victim.UserID); err != nil {
		t.Fatalf("DeleteSessionsByUserID: %v", err)
	}
	if _, err := store.FindSessionByHash(ctx, "tenantA", victim.TokenHash); err != sessions.ErrSessionNotFound {
		t.Fatalf("hash after DeleteSessionsByUserID: got %v want ErrSessionNotFound", err)
	}
	if len(store.sessions) != len(store.byHash) {
		t.Fatalf("index drift after DeleteSessionsByUserID: sessions=%d byHash=%d", len(store.sessions), len(store.byHash))
	}
}

// TestUpdateSessionPinsUserIDAndCreatedAt proves that UpdateSession is a token/expiry/last-seen
// mutator only: it must NOT re-bind the session to a different UserID, nor reset CreatedAt (which
// feeds the absolute-lifetime cap). This matches the pgx store, whose UPDATE never writes those
// columns. Regression for TASK-083.
func TestUpdateSessionPinsUserIDAndCreatedAt(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	originalUser := uuid.Must(uuid.NewV7())
	originalCreatedAt := time.Now().Add(-time.Hour)
	sess := &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  "tenantA",
		UserID:    originalUser,
		TokenHash: "h1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: originalCreatedAt,
	}
	if err := store.CreateSession(ctx, "tenantA", sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// A caller attempts to re-bind the user and reset CreatedAt through UpdateSession.
	tampered := *sess
	tampered.UserID = uuid.Must(uuid.NewV7())
	tampered.CreatedAt = time.Now()
	tampered.TokenHash = "h2"
	if err := store.UpdateSession(ctx, "tenantA", &tampered, "h1"); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	found, err := store.FindSessionByHash(ctx, "tenantA", "h2")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if found.UserID != originalUser {
		t.Fatalf("UpdateSession must not change UserID: got %v want %v", found.UserID, originalUser)
	}
	if !found.CreatedAt.Equal(originalCreatedAt) {
		t.Fatalf("UpdateSession must not change CreatedAt: got %v want %v", found.CreatedAt, originalCreatedAt)
	}
}

// TestBindSessionChangesUserID proves the explicit anonymous-to-authenticated upgrade primitive:
// BindSession re-binds the session to a new UserID (and rotates its token), which UpdateSession
// must not do. Regression for TASK-083.
func TestBindSessionChangesUserID(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	anonUser := uuid.Must(uuid.NewV7())
	sess := &sessions.Session{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  "tenantA",
		UserID:    anonUser,
		TokenHash: "anon-h",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := store.CreateSession(ctx, "tenantA", sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	authUser := uuid.Must(uuid.NewV7())
	rebound := *sess
	rebound.UserID = authUser
	rebound.TokenHash = "auth-h"
	if err := store.BindSession(ctx, "tenantA", &rebound, "anon-h"); err != nil {
		t.Fatalf("BindSession: %v", err)
	}

	if _, err := store.FindSessionByHash(ctx, "tenantA", "anon-h"); err != sessions.ErrSessionNotFound {
		t.Fatalf("old token after BindSession: got %v want ErrSessionNotFound", err)
	}
	found, err := store.FindSessionByHash(ctx, "tenantA", "auth-h")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if found.UserID != authUser {
		t.Fatalf("BindSession must change UserID: got %v want %v", found.UserID, authUser)
	}
	if found.ID != sess.ID {
		t.Fatalf("BindSession must keep the same logical session: got %v want %v", found.ID, sess.ID)
	}
}

// TestSameHashDifferentTenants proves the index is tenant-scoped: an identical token
// hash in two tenants resolves independently and stays consistent.
func TestSameHashDifferentTenants(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	future := time.Now().Add(time.Hour)

	a := newSession("tenantA", "shared", future)
	b := newSession("tenantB", "shared", future)
	if err := store.CreateSession(ctx, "tenantA", a); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := store.CreateSession(ctx, "tenantB", b); err != nil {
		t.Fatalf("create B: %v", err)
	}

	gotA, err := store.FindSessionByHash(ctx, "tenantA", "shared")
	if err != nil || gotA.ID != a.ID {
		t.Fatalf("tenantA lookup: got %v err %v want %v", gotA, err, a.ID)
	}
	gotB, err := store.FindSessionByHash(ctx, "tenantB", "shared")
	if err != nil || gotB.ID != b.ID {
		t.Fatalf("tenantB lookup: got %v err %v want %v", gotB, err, b.ID)
	}
}

// TestEvictExpiredOnRead proves an expired session is removed from both maps when
// looked up, returning ErrSessionNotFound, without an O(n) sweep.
func TestEvictExpiredOnRead(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	expired := newSession("tenantA", "stale", time.Now().Add(-time.Minute))
	if err := store.CreateSession(ctx, "tenantA", expired); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// A live session must survive the eviction of the expired one.
	live := newSession("tenantA", "fresh", time.Now().Add(time.Hour))
	if err := store.CreateSession(ctx, "tenantA", live); err != nil {
		t.Fatalf("CreateSession live: %v", err)
	}

	if _, err := store.FindSessionByHash(ctx, "tenantA", "stale"); err != sessions.ErrSessionNotFound {
		t.Fatalf("expired lookup: got %v want ErrSessionNotFound", err)
	}

	// The expired session must be gone from both maps; the live one untouched.
	if _, ok := store.sessions[expired.ID]; ok {
		t.Fatalf("expired session still in primary map after read")
	}
	if len(store.sessions) != 1 || len(store.byHash) != 1 {
		t.Fatalf("eviction did not converge: sessions=%d byHash=%d", len(store.sessions), len(store.byHash))
	}
	if _, err := store.FindSessionByHash(ctx, "tenantA", "fresh"); err != nil {
		t.Fatalf("live session lookup after eviction: %v", err)
	}
}

// TestBoundedStore_NeverExceedsCap verifies that a bounded store never holds
// more than maxSize sessions. When the cap is reached, the oldest session
// (by ExpiresAt) must be evicted before the new one is inserted.
func TestBoundedStore_NeverExceedsCap(t *testing.T) {
	ctx := context.Background()
	const cap = 5
	store := NewBoundedStore(cap)
	future := time.Now().Add(time.Hour)

	// Fill the store to the cap.
	for i := range cap {
		sess := newSession("t1", "hash-"+strconv.Itoa(i), future.Add(time.Duration(i)*time.Second))
		if err := store.CreateSession(ctx, "t1", sess); err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}
	}
	if got := store.Len(); got != cap {
		t.Fatalf("Len() after fill: got %d want %d", got, cap)
	}

	// Adding one more must evict the oldest (hash-0, earliest ExpiresAt) and keep Len == cap.
	extra := newSession("t1", "hash-extra", future.Add(time.Hour))
	if err := store.CreateSession(ctx, "t1", extra); err != nil {
		t.Fatalf("CreateSession extra: %v", err)
	}
	if got := store.Len(); got != cap {
		t.Fatalf("Len() after over-cap insert: got %d want %d", got, cap)
	}

	// The extra session must be findable.
	if _, err := store.FindSessionByHash(ctx, "t1", "hash-extra"); err != nil {
		t.Fatalf("FindSessionByHash extra: %v", err)
	}
}

// TestBoundedStore_EvictsExpiredFirst verifies that already-expired sessions
// are evicted before live ones when the cap is reached.
func TestBoundedStore_EvictsExpiredFirst(t *testing.T) {
	ctx := context.Background()
	const cap = 3
	store := NewBoundedStore(cap)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)

	// Insert one expired and two live sessions.
	expired := newSession("t1", "expired", past)
	live1 := newSession("t1", "live1", future)
	live2 := newSession("t1", "live2", future.Add(time.Second))
	for _, s := range []*sessions.Session{expired, live1, live2} {
		if err := store.CreateSession(ctx, "t1", s); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	// Adding a 4th session must evict the expired one, not the live ones.
	extra := newSession("t1", "extra", future.Add(2*time.Second))
	if err := store.CreateSession(ctx, "t1", extra); err != nil {
		t.Fatalf("CreateSession extra: %v", err)
	}
	if store.Len() != cap {
		t.Fatalf("Len() after eviction: got %d want %d", store.Len(), cap)
	}
	// The expired session must be gone.
	if _, err := store.FindSessionByHash(ctx, "t1", "expired"); err != sessions.ErrSessionNotFound {
		t.Fatalf("expired session survived eviction: err=%v", err)
	}
	// Live sessions must still be present.
	for _, h := range []string{"live1", "live2", "extra"} {
		if _, err := store.FindSessionByHash(ctx, "t1", h); err != nil {
			t.Fatalf("live session %q missing after eviction: %v", h, err)
		}
	}
}

// TestNewStore_Unbounded confirms the existing NewStore constructor
// creates an unbounded store (zero maxSize = no cap).
func TestNewStore_Unbounded(t *testing.T) {
	store := NewStore()
	if store.maxSize != 0 {
		t.Fatalf("NewStore maxSize: got %d want 0 (unbounded)", store.maxSize)
	}
}

// TestBoundedStore_CrossTenantEvictionIsolation confirms SEC-SES-02 (CVSS 7.7).
//
// Security invariant:
// In a multi-tenant shared architecture, capacity limits or eviction policies
// (LRU/TTL) of a session store MUST be strictly partitioned per tenant.
// Mass session creation by Tenant A (or Tenant A exceeding its quota)
// MUST NEVER evict or destroy valid active sessions belonging to Tenant B (cross-tenant Denial of Service).
//
// Current vulnerable behaviour:
// sessions/memory.BoundedStore uses a single global counter (s.maxSize) and its evictOne() method
// indiscriminately iterates over all sessions from all tenants. Once the global capacity
// is reached, eviction destroys the session with the nearest expiry, even if
// it belongs to a completely different tenant. A Tenant A user can thereby log out
// and arbitrarily block Tenant B users.
func TestBoundedStore_CrossTenantEvictionIsolation(t *testing.T) {
	ctx := context.Background()
	const cap = 2
	store := NewBoundedStore(cap)
	now := time.Now()

	// 1. Tenant B creates a legitimate active session (expires in 1 hour)
	sessB := newSession("tenant-b", "hash-victim-b", now.Add(1*time.Hour))
	err := store.CreateSession(ctx, "tenant-b", sessB)
	require.NoError(t, err)

	// 2. Tenant A creates a first session (expires in 2 hours)
	sessA1 := newSession("tenant-a", "hash-attacker-a1", now.Add(2*time.Hour))
	err = store.CreateSession(ctx, "tenant-a", sessA1)
	require.NoError(t, err)

	// Global capacity is reached (2/2)
	assert.Equal(t, cap, store.Len())

	// 3. Tenant A creates a second session (expires in 3 hours)
	sessA2 := newSession("tenant-a", "hash-attacker-a2", now.Add(3*time.Hour))
	err = store.CreateSession(ctx, "tenant-a", sessA2)
	require.NoError(t, err)

	// 4. SECURITY INVARIANT VIOLATED:
	// Tenant A's activity or capacity overflow must not under any circumstances destroy
	// Tenant B's valid session.
	gotB, err := store.FindSessionByHash(ctx, "tenant-b", "hash-victim-b")
	require.NoError(t, err, "SEC-SES-02: Tenant B's active session must not be evicted by a Tenant A overflow")
	assert.NotNil(t, gotB)
	assert.Equal(t, sessB.ID, gotB.ID)
}
