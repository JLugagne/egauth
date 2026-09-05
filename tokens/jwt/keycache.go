// CachingKeyStore wraps a KeyStore with a bounded-TTL, per-tenant in-memory cache so a single
// request (and the many that follow it within the TTL) does not re-hit the backing key store —
// typically a database — for every sign and verify. It is an opt-in, additive decorator: the
// zero-config jwt.Service and any directly-wired KeyStore keep their previous behavior. Wrap an
// existing KeyStore and pass the result as Config.KeyStore:
//
//	cache := jwt.NewCachingKeyStore(backing, 30*time.Second)
//	svc := jwt.New(jwt.Config[C]{KeyStore: cache, ...})
//
// Staleness is bounded two ways. First, every cached entry expires after the configured TTL, so a
// rotation or revocation is picked up within at most one TTL even with no explicit signal. Second,
// CachingKeyStore is an event.Sink: wiring it as (one of) the keystore.Manager's event sinks makes
// it invalidate a tenant's entry IMMEDIATELY on EventTenantKeysRenewed (rotation),
// EventTenantKeysRevoked (compromise response) and EventTenantDeleted, closing the staleness window
// to zero for those operations. Invalidate / InvalidateAll are also exported for callers that
// rotate keys out of band.
package jwt

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/JLugagne/egauth/event"
)

// DefaultKeyCacheTTL is the bounded staleness window used when NewCachingKeyStore is given a
// non-positive TTL. It is short enough that a rotation is honored quickly even without an event
// sink wired, yet long enough to absorb a burst of requests for the same tenant.
const DefaultKeyCacheTTL = 30 * time.Second

// DefaultKeyCacheMaxEntries is the upper bound on cached tenant keysets when NewCachingKeyStore is
// constructed without an explicit capacity option.
const DefaultKeyCacheMaxEntries = 10000

// Event types that must drop a tenant's cached keyset the moment they fire. They mirror the
// keystore.Manager lifecycle events by value, so wiring a CachingKeyStore as a Manager event sink
// needs no import of (and no dependency on) the keystore package — preserving tokens/jwt's tiny
// KeyStore contract.
const (
	evtKeysRenewed   = "tenant.keys_renewed"
	evtKeysRevoked   = "tenant.keys_revoked"
	evtTenantDeleted = "tenant.deleted"
)

// cachedKeyset is one tenant's resolved material plus the instant it was cached.
type cachedKeyset struct {
	active   Signer
	verify   map[string]Signer
	cachedAt time.Time
}

// CachingKeyStore is a KeyStore decorator adding a bounded-TTL per-tenant cache with explicit and
// event-driven invalidation. It is safe for concurrent use.
type CachingKeyStore struct {
	delegate   KeyStore
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	entries map[string]cachedKeyset
	// gen is bumped on every Invalidate/InvalidateAll. A fill captures it before reading the
	// delegate and store() writes only if it is unchanged, so an invalidation that races an
	// in-flight fill is never lost (it would otherwise re-cache a pre-invalidation keyset).
	gen uint64
}

// CachingKeyStoreOption configures a CachingKeyStore.
type CachingKeyStoreOption func(*CachingKeyStore)

// WithCacheClock overrides the clock used to age cache entries. It exists for deterministic tests;
// production callers never need it.
func WithCacheClock(now func() time.Time) CachingKeyStoreOption {
	return func(c *CachingKeyStore) {
		if now != nil {
			c.now = now
		}
	}
}

// WithCacheMaxEntries bounds the maximum number of tenant entries retained in the cache. A
// non-positive limit selects DefaultKeyCacheMaxEntries.
func WithCacheMaxEntries(maxEntries int) CachingKeyStoreOption {
	return func(c *CachingKeyStore) {
		if maxEntries <= 0 {
			c.maxEntries = DefaultKeyCacheMaxEntries
			return
		}
		c.maxEntries = maxEntries
	}
}

// NewCachingKeyStore wraps delegate with a cache whose entries live for at most ttl. A non-positive
// ttl selects DefaultKeyCacheTTL. It panics on a nil delegate (a programming error caught at
// startup rather than as a nil dereference on the first request), matching jwt.New's fail-fast
// convention.
func NewCachingKeyStore(delegate KeyStore, ttl time.Duration, opts ...CachingKeyStoreOption) *CachingKeyStore {
	if delegate == nil {
		panic("jwt: NewCachingKeyStore requires a non-nil delegate KeyStore")
	}
	if ttl <= 0 {
		ttl = DefaultKeyCacheTTL
	}
	c := &CachingKeyStore{
		delegate:   delegate,
		ttl:        ttl,
		maxEntries: DefaultKeyCacheMaxEntries,
		now:        time.Now,
		entries:    make(map[string]cachedKeyset),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// lookup returns a non-expired cached entry for tenantID, if any.
func (c *CachingKeyStore) lookup(tenantID string) (cachedKeyset, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return cachedKeyset{}, false
	}
	if c.now().Sub(e.cachedAt) >= c.ttl {
		delete(c.entries, tenantID)
		return cachedKeyset{}, false
	}
	return e, true
}

// generation returns the current invalidation counter, captured by a fill before it reads the
// delegate so store can detect an invalidation that raced the fill.
func (c *CachingKeyStore) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// store records a resolved keyset for tenantID. Both fields are populated together so the active
// key and the verification set served from cache are always from the same backing read. seenGen is
// the invalidation counter observed before the delegate read; if it has since changed, an
// Invalidate landed mid-fill and this (now-stale) keyset is dropped rather than cached.
func (c *CachingKeyStore) store(tenantID string, active Signer, verify map[string]Signer, seenGen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != seenGen {
		return
	}
	if len(c.entries) >= c.maxEntries {
		now := c.now()
		for id, e := range c.entries {
			if now.Sub(e.cachedAt) >= c.ttl {
				delete(c.entries, id)
			}
		}
		if len(c.entries) >= c.maxEntries {
			if _, exists := c.entries[tenantID]; !exists {
				var oldestID string
				var oldestTime time.Time
				first := true
				for id, e := range c.entries {
					if first || e.cachedAt.Before(oldestTime) {
						oldestID = id
						oldestTime = e.cachedAt
						first = false
					}
				}
				if !first {
					delete(c.entries, oldestID)
				}
			}
		}
	}
	c.entries[tenantID] = cachedKeyset{active: active, verify: verify, cachedAt: c.now()}
}

// ActiveSigningKey returns the tenant's active key, serving a cached value when fresh and otherwise
// resolving both the active key and the verification set from the delegate in one fill so a later
// VerificationKeys call for the same tenant is served from cache.
func (c *CachingKeyStore) ActiveSigningKey(ctx context.Context, tenantID string) (Signer, error) {
	if e, ok := c.lookup(tenantID); ok {
		return e.active, nil
	}
	seenGen := c.generation()
	active, err := c.delegate.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	verify, err := c.delegate.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c.store(tenantID, active, verify, seenGen)
	return active, nil
}

// VerificationKeys returns every key that may still verify a token for tenantID, served from cache
// when fresh. A defensive copy is returned so a caller cannot mutate the cached map. It fills both
// halves of the entry on a miss for the same reason as ActiveSigningKey.
func (c *CachingKeyStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]Signer, error) {
	if e, ok := c.lookup(tenantID); ok {
		return cloneKeys(e.verify), nil
	}
	seenGen := c.generation()
	active, err := c.delegate.ActiveSigningKey(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	verify, err := c.delegate.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c.store(tenantID, active, verify, seenGen)
	return cloneKeys(verify), nil
}

// Invalidate drops the cached entry for tenantID so the next resolution re-reads the delegate. It
// is safe to call for a tenant that is not cached.
func (c *CachingKeyStore) Invalidate(tenantID string) {
	c.mu.Lock()
	delete(c.entries, tenantID)
	c.gen++
	c.mu.Unlock()
}

// InvalidateAll drops every cached entry.
func (c *CachingKeyStore) InvalidateAll() {
	c.mu.Lock()
	c.entries = make(map[string]cachedKeyset)
	c.gen++
	c.mu.Unlock()
}

// Len returns the current number of cached tenant entries.
func (c *CachingKeyStore) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// EmitEvent implements event.Sink so the cache can be wired as one of the keystore.Manager's sinks
// and invalidate a tenant the instant its keys are renewed, revoked or deleted — bounding staleness
// to zero for those operations rather than to the TTL. Unrelated event types are ignored.
func (c *CachingKeyStore) EmitEvent(_ context.Context, e event.Event) {
	switch string(e.Type) {
	case evtKeysRenewed, evtKeysRevoked, evtTenantDeleted:
		c.Invalidate(e.TenantID)
	}
}

// cloneKeys returns a shallow copy of a kid->key map so cached state cannot be mutated by callers.
func cloneKeys(in map[string]Signer) map[string]Signer {
	if in == nil {
		return nil
	}
	out := make(map[string]Signer, len(in))
	maps.Copy(out, in)
	return out
}
