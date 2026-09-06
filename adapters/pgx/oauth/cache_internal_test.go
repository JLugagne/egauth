package pgx

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRow is a pgx.Row that scans a fixed, valid OIDC provider configuration.
type fakeRow struct{}

func (fakeRow) Scan(dest ...any) error {
	// Column order matches GetProvider's SELECT:
	// client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes
	values := []any{
		"client-id",
		base64.StdEncoding.EncodeToString([]byte("client-secret")),
		"https://sso.example.com/auth",
		"https://sso.example.com/token",
		"https://sso.example.com",
		"https://sso.example.com/jwks",
		"openid email profile",
		time.Time{},
	}
	for i := range dest {
		if i == 7 {
			p, ok := dest[i].(*time.Time)
			if !ok {
				return fmt.Errorf("fakeRow: dest[%d] is not *time.Time", i)
			}
			*p = time.Time{}
			continue
		}
		p, ok := dest[i].(*string)
		if !ok {
			return fmt.Errorf("fakeRow: dest[%d] is not *string", i)
		}
		*p = values[i].(string)
	}
	return nil
}

// countingQuerier is a DBQuerier that records how many times QueryRow (the
// per-GetProvider database read) is invoked. It returns a fixed valid row so
// GetProvider always succeeds without a live database.
type countingQuerier struct {
	queryRowCalls int
}

func (c *countingQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (c *countingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, nil
}

func (c *countingQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	c.queryRowCalls++
	return fakeRow{}
}

// TestGetProviderCachesBuiltProvider is the regression test for TASK-086: a dynamic
// ProviderStore must not rebuild the oauth.Provider (and its JWKS cache) on every call.
// Two GetProvider calls for the same (tenant, provider) must hit the DB once and return
// the very same *oauth.Provider instance, so the verifier's 1h JWKS cache survives requests.
func TestGetProviderCachesBuiltProvider(t *testing.T) {
	q := &countingQuerier{}
	store := NewStore(q, dummyKEK{})
	ctx := context.Background()

	p1, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("first GetProvider: %v", err)
	}
	p2, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("second GetProvider: %v", err)
	}

	if p1 != p2 {
		t.Errorf("GetProvider returned distinct instances (%p vs %p); the per-request rebuild defeats the JWKS cache", p1, p2)
	}
	if q.queryRowCalls != 2 {
		t.Errorf("expected 2 DB reads across two GetProvider calls, got %d", q.queryRowCalls)
	}
}

// TestGetProviderCacheInvalidation verifies that UpsertProvider and DeleteProvider drop the
// cached instance so a subsequent GetProvider re-reads from the database.
func TestGetProviderCacheInvalidation(t *testing.T) {
	q := &countingQuerier{}
	store := NewStore(q, dummyKEK{})
	ctx := context.Background()

	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("warm GetProvider: %v", err)
	}

	// Upsert must invalidate the cache for that (tenant, provider).
	if err := store.UpsertProvider(ctx, "tenant-1", "my-sso", OIDCProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      "https://sso.example.com/auth",
		TokenURL:     "https://sso.example.com/token",
		Issuer:       "https://sso.example.com",
		Scopes:       []string{"openid"},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	before := q.queryRowCalls
	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("post-upsert GetProvider: %v", err)
	}
	if q.queryRowCalls != before+1 {
		t.Errorf("expected a DB re-read after UpsertProvider, got %d (was %d)", q.queryRowCalls, before)
	}

	// Delete must invalidate too.
	if err := store.DeleteProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	before = q.queryRowCalls
	if _, err := store.GetProvider(ctx, "tenant-1", "my-sso"); err != nil {
		t.Fatalf("post-delete GetProvider: %v", err)
	}
	if q.queryRowCalls != before+1 {
		t.Errorf("expected a DB re-read after DeleteProvider, got %d (was %d)", q.queryRowCalls, before)
	}
}

// TestGetProviderCache_BoundedCapacity verifies that providerCache is bounded to maxCachedProviders
// and evicts the least recently used entry when capacity is reached (SEC-OAU-10).
func TestGetProviderCache_BoundedCapacity(t *testing.T) {
	q := &countingQuerier{}
	store := NewStore(q, dummyKEK{}, WithMaxCachedProviders(3))
	ctx := context.Background()

	p1, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-1: %v", err)
	}
	p2, err := store.GetProvider(ctx, "tenant-2", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-2: %v", err)
	}
	_, err = store.GetProvider(ctx, "tenant-3", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-3: %v", err)
	}

	// Access tenant-1 so it is recently used.
	// Order from oldest to newest: tenant-2, tenant-3, tenant-1.
	p1Again, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-1: %v", err)
	}
	if p1Again != p1 {
		t.Fatalf("expected tenant-1 to be cached")
	}

	// Insert tenant-4. Capacity (3) exceeded, so tenant-2 should be evicted.
	_, err = store.GetProvider(ctx, "tenant-4", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-4: %v", err)
	}

	store.mu.RLock()
	cacheLen := len(store.providerCache)
	store.mu.RUnlock()

	if cacheLen > 3 {
		t.Errorf("cache capacity exceeded: got %d, expected max 3", cacheLen)
	}

	// tenant-1 should still be cached (same pointer)
	p1After, err := store.GetProvider(ctx, "tenant-1", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-1: %v", err)
	}
	if p1After != p1 {
		t.Errorf("tenant-1 was unexpectedly evicted")
	}

	// tenant-2 was evicted, so it must return a new pointer
	p2After, err := store.GetProvider(ctx, "tenant-2", "my-sso")
	if err != nil {
		t.Fatalf("GetProvider tenant-2: %v", err)
	}
	if p2After == p2 {
		t.Errorf("tenant-2 was expected to be evicted, but was still cached")
	}
}
