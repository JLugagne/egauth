package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of tokens.Store.
type Store[C any] struct {
	mu sync.RWMutex
	// refreshTokens stores full RefreshToken records keyed by hash.
	// SECURITY: only the hash is ever stored, never the clear-text token.
	refreshTokens map[string]*tokens.RefreshToken
	apiKeys       map[string]*tokens.APIKey[C]
}

// NewStore creates a new in-memory tokens Store.
func NewStore[C any]() *Store[C] {
	return &Store[C]{
		refreshTokens: make(map[string]*tokens.RefreshToken),
		apiKeys:       make(map[string]*tokens.APIKey[C]),
	}
}

func tenantFromOpts(rtTenant string, opts []tokens.Option) string {
	opt := tokens.ApplyOptions(opts)
	if opt.TenantID != nil {
		return *opt.TenantID
	}
	return rtTenant
}

// DeleteExpired purges expired refresh tokens and expired API keys (API keys with no expiry are
// kept), returning the number deleted. With WithTenant it sweeps a single tenant, otherwise all.
func (s *Store[C]) DeleteExpired(ctx context.Context, opts ...tokens.Option) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := tokens.ApplyOptions(opts)
	now := time.Now()
	var deleted int64

	for hash, rt := range s.refreshTokens {
		if opt.TenantID != nil && rt.TenantID != *opt.TenantID {
			continue
		}
		if rt.ExpiresAt.Before(now) {
			delete(s.refreshTokens, hash)
			deleted++
		}
	}
	for hash, key := range s.apiKeys {
		if opt.TenantID != nil && key.TenantID != *opt.TenantID {
			continue
		}
		if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
			delete(s.apiKeys, hash)
			deleted++
		}
	}
	return deleted, nil
}

// SaveRefreshToken persists a refresh token record (storing only its hash).
func (s *Store[C]) SaveRefreshToken(ctx context.Context, rt *tokens.RefreshToken, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rtCopy := *rt
	rtCopy.TenantID = tenantFromOpts(rt.TenantID, opts)
	if rtCopy.ConsumedAt != nil {
		consumed := *rtCopy.ConsumedAt
		rtCopy.ConsumedAt = &consumed
	}
	s.refreshTokens[rtCopy.Hash] = &rtCopy

	return nil
}

// FindRefreshToken retrieves a refresh token by its hash, including its ConsumedAt state.
func (s *Store[C]) FindRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantID := tenantFromOpts("", opts)

	entry, exists := s.refreshTokens[tokenHash]
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
func (s *Store[C]) ConsumeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID := tenantFromOpts("", opts)

	entry, exists := s.refreshTokens[tokenHash]
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

// RevokeRefreshToken deletes/revokes a single refresh token by its hash.
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID := tenantFromOpts("", opts)

	rt, exists := s.refreshTokens[tokenHash]
	if !exists || rt.TenantID != tenantID {
		return tokens.ErrRefreshTokenNotFound
	}

	delete(s.refreshTokens, tokenHash)

	return nil
}

// RevokeFamily revokes ALL refresh tokens sharing the given family ID.
func (s *Store[C]) RevokeFamily(ctx context.Context, familyID uuid.UUID, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID := tenantFromOpts("", opts)

	for hash, rt := range s.refreshTokens {
		if rt.TenantID == tenantID && rt.FamilyID == familyID {
			delete(s.refreshTokens, hash)
		}
	}

	return nil
}

// SaveAPIKey persists an API key.
func (s *Store[C]) SaveAPIKey(ctx context.Context, key *tokens.APIKey[C], opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kCopy := *key
	kCopy.Token = "" // SECURITY: do not store the clear-text token

	// Ensure the key has the correct tenant ID if provided in options
	opt := tokens.ApplyOptions(opts)
	if opt.TenantID != nil {
		kCopy.TenantID = *opt.TenantID
	}

	s.apiKeys[kCopy.Hash] = &kCopy

	return nil
}

// FindAPIKeyByHash retrieves an API key by its hash.
func (s *Store[C]) FindAPIKeyByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (*tokens.APIKey[C], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := tokens.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	key, exists := s.apiKeys[tokenHash]
	if !exists || key.TenantID != tenantID {
		return nil, tokens.ErrAPIKeyNotFound
	}

	kCopy := *key
	return &kCopy, nil
}

// Verify interface compliance
var _ tokens.Store[any] = (*Store[any])(nil)
