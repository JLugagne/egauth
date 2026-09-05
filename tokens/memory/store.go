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
type Store[C any] struct {
	mu sync.RWMutex
	// refreshTokens stores full RefreshToken records keyed by (tenantID, hash).
	// SECURITY: only the hash is ever stored, never the clear-text token.
	refreshTokens map[tokenKey]*tokens.RefreshToken
	apiKeys       map[tokenKey]*tokens.APIKey[C]
}

// NewStore creates a new in-memory tokens Store.
func NewStore[C any]() *Store[C] {
	return &Store[C]{
		refreshTokens: make(map[tokenKey]*tokens.RefreshToken),
		apiKeys:       make(map[tokenKey]*tokens.APIKey[C]),
	}
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
	s.refreshTokens[tokenKey{tenantID: tenantID, hash: rtCopy.Hash}] = &rtCopy

	return nil
}

// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
func (s *Store[C]) FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*tokens.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.refreshTokens[tokenKey{tenantID: tenantID, hash: tokenHash}]
	if !exists || entry.TenantID != tenantID {
		return nil, tokens.ErrRefreshTokenNotFound
	}

	rtCopy := *entry
	if entry.ConsumedAt != nil {
		consumed := *entry.ConsumedAt
		rtCopy.ConsumedAt = &consumed
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
	s.refreshTokens[tokenKey{tenantID: tenantID, hash: rtCopy.Hash}] = &rtCopy

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

// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
func (s *Store[C]) RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, rt := range s.refreshTokens {
		if key.tenantID == tenantID && rt.FamilyID == familyID {
			delete(s.refreshTokens, key)
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
