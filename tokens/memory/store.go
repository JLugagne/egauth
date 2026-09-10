// Package memory provides an in-memory tokens.Store, primarily for tests and single-process use.
//
// # Bounding memory growth
//
// [NewStore] is bounded by default: it retains at most [DefaultMaxEntries] refresh-token records
// and evicts expired records first, then the record expiring soonest. Consumed refresh tokens are
// retained until their expiry for reuse/theft detection, so a busy rotation family would otherwise
// grow the map without limit.
//
// API keys are durable credentials belonging to an authenticated creator, so they are never
// silently evicted; revoke them explicitly with [Store.RevokeAPIKey] /
// [Store.RevokeAllAPIKeysForUser] instead. Use [NewBoundedStore] to pick a different refresh-token
// cap or [NewUnboundedStore] for the previous unbounded behaviour, where
// [Store.DeleteExpired] must be scheduled periodically.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// tokenKey is a composite key used to partition in-memory token storage by tenant.
type tokenKey struct {
	tenantID string
	hash     string
}

// Store is an in-memory implementation of tokens.Store.
//
// Stores created by [NewStore] cap refresh-token records at [DefaultMaxEntries];
// API keys are durable and are never evicted.
type Store[C any] struct {
	mu sync.RWMutex
	// maxRefreshTokens caps the refreshTokens map; 0 means unbounded.
	maxRefreshTokens int
	// refreshTokens stores full RefreshToken records keyed by (tenantID, hash).
	// SECURITY: only the hash is ever stored, never the clear-text token.
	refreshTokens map[tokenKey]*tokens.RefreshToken
	apiKeys       map[tokenKey]*tokens.APIKey[C]
}

// DefaultMaxEntries is the default hard cap on the number of refresh-token records an in-memory
// Store created by [NewStore] retains. It is deliberately generous so ordinary single-process use
// never hits it; it exists so a flood of logins or refreshes cannot exhaust memory. On insertion
// at the cap the store evicts expired records first, then the record expiring soonest.
const DefaultMaxEntries = 100_000

// NewStore creates a new in-memory tokens Store whose refresh-token records are
// bounded by [DefaultMaxEntries]. Callers that schedule periodic
// [Store.DeleteExpired] eviction and want no hard cap can use
// [NewUnboundedStore] instead.
func NewStore[C any]() *Store[C] {
	return NewBoundedStore[C](DefaultMaxEntries)
}

// NewBoundedStore creates a new in-memory tokens Store that retains at most
// maxSize refresh-token records. When a new record is inserted at the cap the
// store evicts expired records first, then the record expiring soonest. API keys
// are durable credentials and are never evicted. maxSize must be >= 1; values
// below 1 are floored to 1.
func NewBoundedStore[C any](maxSize int) *Store[C] {
	if maxSize < 1 {
		maxSize = 1
	}
	return &Store[C]{
		maxRefreshTokens: maxSize,
		refreshTokens:    make(map[tokenKey]*tokens.RefreshToken),
		apiKeys:          make(map[tokenKey]*tokens.APIKey[C]),
	}
}

// NewUnboundedStore creates a new in-memory tokens Store with no cap on
// refresh-token records. Growth is controlled entirely by periodic
// [Store.DeleteExpired] calls; prefer [NewStore]'s bounded default unless the
// caller guarantees that eviction runs.
func NewUnboundedStore[C any]() *Store[C] {
	return &Store[C]{
		refreshTokens: make(map[tokenKey]*tokens.RefreshToken),
		apiKeys:       make(map[tokenKey]*tokens.APIKey[C]),
	}
}

// MaxEntries returns the configured hard cap on the number of refresh-token
// records the store retains. Zero means the store is unbounded (see
// [NewUnboundedStore]).
func (s *Store[C]) MaxEntries() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxRefreshTokens
}

// DeleteExpired purges expired refresh tokens and expired API keys (API keys with no expiry are
// kept) within the given tenant, returning the number deleted.
func (s *Store[C]) DeleteExpired(ctx context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var deleted int64

	for key, rt := range s.refreshTokens {
		if key.tenantID != tenantID {
			continue
		}
		if rt.ExpiresAt.Before(now) {
			delete(s.refreshTokens, key)
			deleted++
		}
	}
	for key, apiKey := range s.apiKeys {
		if key.tenantID != tenantID {
			continue
		}
		if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(now) {
			delete(s.apiKeys, key)
			deleted++
		}
	}
	return deleted, nil
}

// SaveRefreshToken persists a refresh token record (storing only its hash).
func (s *Store[C]) SaveRefreshToken(ctx context.Context, tenantID string, rt *tokens.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rt.TenantID != "" && rt.TenantID != tenantID {
		return tokens.ErrTenantMismatch
	}
	rtCopy := *rt
	rtCopy.TenantID = tenantID
	if rtCopy.ConsumedAt != nil {
		consumed := *rtCopy.ConsumedAt
		rtCopy.ConsumedAt = &consumed
	}
	if rtCopy.RevokedAt != nil {
		revoked := *rtCopy.RevokedAt
		rtCopy.RevokedAt = &revoked
	}
	k := tokenKey{tenantID: tenantID, hash: rtCopy.Hash}
	if _, exists := s.refreshTokens[k]; !exists && s.maxRefreshTokens > 0 && len(s.refreshTokens) >= s.maxRefreshTokens {
		s.evictRefreshTokenLocked()
	}
	s.refreshTokens[k] = &rtCopy

	return nil
}

// evictRefreshTokenLocked removes one refresh-token record to make room for a new
// one: the expired record with the earliest expiry first, otherwise the record
// with the soonest ExpiresAt (which may be a consumed record retained for replay
// detection). Must be called with the write lock held.
func (s *Store[C]) evictRefreshTokenLocked() {
	now := time.Now()
	var (
		victim   tokenKey
		victimAt time.Time
		found    bool
	)
	for k, rt := range s.refreshTokens {
		if rt.ExpiresAt.Before(now) {
			if !found || rt.ExpiresAt.Before(victimAt) {
				victim, victimAt, found = k, rt.ExpiresAt, true
			}
		}
	}
	if !found {
		for k, rt := range s.refreshTokens {
			if !found || rt.ExpiresAt.Before(victimAt) {
				victim, victimAt, found = k, rt.ExpiresAt, true
			}
		}
	}
	if found {
		delete(s.refreshTokens, victim)
	}
}

// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
func (s *Store[C]) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.refreshTokens[tokenKey{tenantID: tenantID, hash: tokenHash}]
	if !exists || entry.TenantID != tenantID {
		return nil, tokens.ErrRefreshTokenNotFound
	}

	if entry.RevokedAt != nil {
		return nil, tokens.ErrTokenFamilyRevoked
	}

	rtCopy := *entry
	if entry.ConsumedAt != nil {
		consumed := *entry.ConsumedAt
		rtCopy.ConsumedAt = &consumed
	}
	if entry.RevokedAt != nil {
		revoked := *entry.RevokedAt
		rtCopy.RevokedAt = &revoked
	}
	return &rtCopy, nil
}

// ConsumeRefreshToken atomically marks a refresh token as consumed (single-use).
func (s *Store[C]) ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.refreshTokens[tokenKey{tenantID: tenantID, hash: tokenHash}]
	if !exists || entry.TenantID != tenantID {
		return tokens.ErrRefreshTokenNotFound
	}

	if entry.RevokedAt != nil {
		return tokens.ErrTokenFamilyRevoked
	}

	if entry.ConsumedAt != nil {
		return tokens.ErrRefreshTokenReused
	}

	now := time.Now().UTC()
	entry.ConsumedAt = &now

	return nil
}

// RotateRefreshToken atomically marks oldTokenHash as consumed and persists newRT within the tenant.
// If the old token does not exist, it returns ErrRefreshTokenNotFound.
// If the old token was already consumed, it returns ErrRefreshTokenReused.
// If saving the new token fails (e.g. tenant mismatch), the old token is not marked consumed.
func (s *Store[C]) RotateRefreshToken(ctx context.Context, tenantID string, oldTokenHash string, newRT *tokens.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.refreshTokens[tokenKey{tenantID: tenantID, hash: oldTokenHash}]
	if !exists || entry.TenantID != tenantID {
		return tokens.ErrRefreshTokenNotFound
	}

	if entry.RevokedAt != nil {
		return tokens.ErrTokenFamilyRevoked
	}

	if entry.ConsumedAt != nil {
		return tokens.ErrRefreshTokenReused
	}

	if newRT.TenantID != "" && newRT.TenantID != tenantID {
		return tokens.ErrTenantMismatch
	}

	now := time.Now().UTC()
	entry.ConsumedAt = &now

	rtCopy := *newRT
	rtCopy.TenantID = tenantID
	if rtCopy.ConsumedAt != nil {
		consumed := *rtCopy.ConsumedAt
		rtCopy.ConsumedAt = &consumed
	}
	if rtCopy.RevokedAt != nil {
		revoked := *rtCopy.RevokedAt
		rtCopy.RevokedAt = &revoked
	}
	newKey := tokenKey{tenantID: tenantID, hash: rtCopy.Hash}
	if _, exists := s.refreshTokens[newKey]; !exists && s.maxRefreshTokens > 0 && len(s.refreshTokens) >= s.maxRefreshTokens {
		s.evictRefreshTokenLocked()
	}
	s.refreshTokens[newKey] = &rtCopy

	return nil
}

// RevokeRefreshToken deletes/revokes a single refresh token by its hash.
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := tokenKey{tenantID: tenantID, hash: tokenHash}
	rt, exists := s.refreshTokens[key]
	if !exists || rt.TenantID != tenantID {
		return tokens.ErrRefreshTokenNotFound
	}

	delete(s.refreshTokens, key)

	return nil
}

// RevokeFamily revokes ALL refresh tokens sharing the given family ID by stamping RevokedAt.
func (s *Store[C]) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, rt := range s.refreshTokens {
		if rt.TenantID == tenantID && rt.FamilyID == familyID {
			if rt.RevokedAt == nil {
				revoked := now
				rt.RevokedAt = &revoked
			}
		}
	}

	return nil
}

// RevokeAllRefreshTokensForUser revokes EVERY refresh token belonging to userID within tenantID.
// Idempotent: a user with no live refresh tokens is a no-op returning nil.
func (s *Store[C]) RevokeAllRefreshTokensForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, rt := range s.refreshTokens {
		if key.tenantID == tenantID && rt.UserID == userID {
			delete(s.refreshTokens, key)
		}
	}

	return nil
}

// SaveAPIKey persists an API key.
func (s *Store[C]) SaveAPIKey(ctx context.Context, tenantID string, key *tokens.APIKey[C]) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.TenantID != "" && key.TenantID != tenantID {
		return tokens.ErrTenantMismatch
	}

	kCopy := *key
	kCopy.Token = "" // SECURITY: do not store the clear-text token
	kCopy.TenantID = tenantID

	s.apiKeys[tokenKey{tenantID: tenantID, hash: kCopy.Hash}] = &kCopy

	return nil
}

// FindAPIKeyByHash retrieves an API key by its hash.
func (s *Store[C]) FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*tokens.APIKey[C], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.apiKeys[tokenKey{tenantID: tenantID, hash: tokenHash}]
	if !exists || key.TenantID != tenantID {
		return nil, tokens.ErrAPIKeyNotFound
	}

	kCopy := *key
	return &kCopy, nil
}

// Verify interface compliance
var (
	_ tokens.Store[any]                = (*Store[any])(nil)
	_ tokens.AtomicRefreshTokenRotator = (*Store[any])(nil)
)

// RevokeAPIKey soft-revokes the API key identified by keyID within tenantID.
func (s *Store[C]) RevokeAPIKey(ctx context.Context, tenantID string, keyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, apiKey := range s.apiKeys {
		if key.tenantID == tenantID && apiKey.ID == keyID {
			if apiKey.RevokedAt != nil {
				return nil // idempotent
			}
			now := time.Now()
			apiKey.RevokedAt = &now
			return nil
		}
	}
	return tokens.ErrAPIKeyNotFound
}

// RevokeAllAPIKeysForUser soft-revokes EVERY API key created by userID within tenantID. Already
// -revoked keys keep their original RevokedAt. Idempotent: a user with no keys is a no-op.
func (s *Store[C]) RevokeAllAPIKeysForUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, apiKey := range s.apiKeys {
		if key.tenantID == tenantID && apiKey.CreatedBy == userID && apiKey.RevokedAt == nil {
			revoked := now
			apiKey.RevokedAt = &revoked
		}
	}

	return nil
}

// ListAPIKeysByCreator returns every API key created by createdBy within tenantID.
// The Token field is always blank; the clear-text value exists only at creation.
func (s *Store[C]) ListAPIKeysByCreator(ctx context.Context, tenantID string, createdBy uuid.UUID) ([]*tokens.APIKey[C], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*tokens.APIKey[C]
	for key, apiKey := range s.apiKeys {
		if key.tenantID == tenantID && apiKey.CreatedBy == createdBy {
			kCopy := *apiKey
			kCopy.Token = ""
			result = append(result, &kCopy)
		}
	}
	if result == nil {
		result = []*tokens.APIKey[C]{}
	}
	return result, nil
}
