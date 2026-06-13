package pgx

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRow is a pgx.Row that scans a fixed, valid OIDC provider configuration.
type fakeRow struct{}

func (fakeRow) Scan(dest ...any) error {
	// Column order matches GetProvider's SELECT:
	// client_id, client_secret, auth_url, token_url, issuer, jwks_url, scopes
	values := []string{
		"client-id",
		"client-secret",
		"https://sso.example.com/auth",
		"https://sso.example.com/token",
		"https://sso.example.com",
		"https://sso.example.com/jwks",
		"openid email profile",
	}
	for i := range dest {
		p, ok := dest[i].(*string)
		if !ok {
			return fmt.Errorf("fakeRow: dest[%d] is not *string", i)
		}
		*p = values[i]
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
	store := NewStore(q)
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
	if q.queryRowCalls != 1 {
		t.Errorf("expected 1 DB read across two GetProvider calls, got %d", q.queryRowCalls)
	}
}

// TestGetProviderCacheInvalidation verifies that UpsertProvider and DeleteProvider drop the
// cached instance so a subsequent GetProvider re-reads from the database.
func TestGetProviderCacheInvalidation(t *testing.T) {
	q := &countingQuerier{}
	store := NewStore(q)
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
