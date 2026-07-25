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

// Event types that must drop a tenant's cached keyset the moment they fire. They mirror the
// keystore.Manager lifecycle events by value, so wiring a CachingKeyStore as a Manager event sink
// needs no import of (and no dependency on) the keystore package — preserving tokens/jwt's tiny
// KeyStore contract.
const (
	evtKeysRenewed   = "tenant.keys_renewed"
	evtKeysRevoked   = "tenant.keys_revoked"
	evtTenantDeleted = "tenant.deleted"
)

// cachedKeyset is one tenant's resolved material. The two halves are aged independently because
// they are filled independently: the SIGNING path fills both (it already resolves the active key,
// so reading the verification set in the same pass is free), while the VERIFICATION path fills the
// verification half ALONE — it must never resolve the active key (see VerificationKeys).
type cachedKeyset struct {
	active    Signer
	activeAt  time.Time
	hasActive bool

	verify    map[string]Signer
	verifyAt  time.Time
	hasVerify bool
}

// CachingKeyStore is a KeyStore decorator adding a bounded-TTL per-tenant cache with explicit and
// event-driven invalidation. It is safe for concurrent use.
type CachingKeyStore struct {
	delegate KeyStore
	ttl      time.Duration
	now      func() time.Time

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
		delegate: delegate,
		ttl:      ttl,
		now:      time.Now,
		entries:  make(map[string]cachedKeyset),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// lookupActive returns the tenant's cached active key when that half is present and still fresh.
func (c *CachingKeyStore) lookupActive(tenantID string) (Signer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[tenantID]
	if !ok || !e.hasActive {
		return nil, false
	}
	if c.now().Sub(e.activeAt) >= c.ttl {
		e.active, e.hasActive = nil, false
		c.pruneLocked(tenantID, e)
		return nil, false
	}
	return e.active, true
}

// lookupVerify returns the tenant's cached verification set when that half is present and still
// fresh. The map is the cached one: callers must clone it before handing it out.
func (c *CachingKeyStore) lookupVerify(tenantID string) (map[string]Signer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[tenantID]
	if !ok || !e.hasVerify {
		return nil, false
	}
	if c.now().Sub(e.verifyAt) >= c.ttl {
		e.verify, e.hasVerify = nil, false
		c.pruneLocked(tenantID, e)
		return nil, false
	}
	return e.verify, true
}

// pruneLocked writes back an entry whose halves were just re-evaluated, dropping it entirely once
// neither half holds anything. c.mu must be held.
func (c *CachingKeyStore) pruneLocked(tenantID string, e cachedKeyset) {
	if !e.hasActive && !e.hasVerify {
		delete(c.entries, tenantID)
		return
	}
	c.entries[tenantID] = e
}

// generation returns the current invalidation counter, captured by a fill before it reads the
// delegate so store can detect an invalidation that raced the fill.
func (c *CachingKeyStore) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// storeKeyset records a full fill for tenantID: both halves come from the same pair of delegate
// reads, so the active key and the verification set served from cache are always consistent.
// seenGen is the invalidation counter observed before the delegate read; if it has since changed, an
// Invalidate landed mid-fill and this (now-stale) keyset is dropped rather than cached.
func (c *CachingKeyStore) storeKeyset(tenantID string, active Signer, verify map[string]Signer, seenGen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != seenGen {
		return
	}
	now := c.now()
	c.entries[tenantID] = cachedKeyset{
		active: active, activeAt: now, hasActive: true,
		verify: verify, verifyAt: now, hasVerify: true,
	}
}

// storeVerify records a verification-only fill, leaving any cached active half untouched (it ages
// on its own timestamp). seenGen is honored exactly as in storeKeyset.
func (c *CachingKeyStore) storeVerify(tenantID string, verify map[string]Signer, seenGen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != seenGen {
		return
	}
	e := c.entries[tenantID]
	e.verify, e.verifyAt, e.hasVerify = verify, c.now(), true
	c.entries[tenantID] = e
}

// ActiveSigningKey returns the tenant's active key, serving a cached value when fresh and otherwise
// resolving both the active key and the verification set from the delegate in one fill so a later
// VerificationKeys call for the same tenant is served from cache. This is the SIGNING path: it runs
// for an authenticated, authorized issuance, which is where a delegate that provisions lazily is
// allowed to do so.
func (c *CachingKeyStore) ActiveSigningKey(ctx context.Context, tenantID string) (Signer, error) {
	if active, ok := c.lookupActive(tenantID); ok {
		return active, nil
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
	c.storeKeyset(tenantID, active, verify, seenGen)
	return active, nil
}

// VerificationKeys returns every key that may still verify a token for tenantID, served from cache
// when fresh. A defensive copy is returned so a caller cannot mutate the cached map.
//
// A miss resolves the VERIFICATION SET ONLY. The verification path is reachable without
// authentication — anyone can present a token, or hit a JWKS endpoint, naming any tenant — so it
// must never resolve the tenant's active signing key: a delegate configured with
// keystore.WithLazyProvisioning provisions the tenant and MINTS a key on that resolution, which
// would hand an anonymous caller a tenant-creation and database-write primitive. Verification is
// therefore strictly read-only with respect to tenant state, and an unknown tenant fails closed
// with the delegate's not-found error.
func (c *CachingKeyStore) VerificationKeys(ctx context.Context, tenantID string) (map[string]Signer, error) {
	if verify, ok := c.lookupVerify(tenantID); ok {
		return cloneKeys(verify), nil
	}
	seenGen := c.generation()
	verify, err := c.delegate.VerificationKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c.storeVerify(tenantID, verify, seenGen)
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
