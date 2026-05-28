package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/google/uuid"
)

type refreshTokenEntry struct {
	tenantID  string
	userID    uuid.UUID
	expiresAt time.Time
}

// Store is an in-memory implementation of tokens.Store.
type Store[C any] struct {
	mu            sync.RWMutex
	refreshTokens map[string]*refreshTokenEntry
	apiKeys       map[string]*tokens.APIKey[C]
}

// NewStore creates a new in-memory tokens Store.
func NewStore[C any]() *Store[C] {
	return &Store[C]{
		refreshTokens: make(map[string]*refreshTokenEntry),
		apiKeys:       make(map[string]*tokens.APIKey[C]),
	}
}

// SaveRefreshToken persists the hash of a refresh token.
func (s *Store[C]) SaveRefreshToken(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := tokens.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	s.refreshTokens[tokenHash] = &refreshTokenEntry{
		tenantID:  tenantID,
		userID:    userID,
		expiresAt: expiresAt,
	}

	return nil
}

// FindRefreshTokenByHash retrieves a refresh token hash information.
func (s *Store[C]) FindRefreshTokenByHash(ctx context.Context, tokenHash string, opts ...tokens.Option) (uuid.UUID, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.refreshTokens[tokenHash]
	if !exists {
		return uuid.Nil, time.Time{}, tokens.ErrRefreshTokenNotFound
	}

	opt := tokens.ApplyOptions(opts)
	if opt.TenantID != nil && entry.tenantID != *opt.TenantID {
		return uuid.Nil, time.Time{}, tokens.ErrRefreshTokenNotFound
	}

	return entry.userID, entry.expiresAt, nil
}

// RevokeRefreshToken marks a refresh token as revoked or deletes it.
func (s *Store[C]) RevokeRefreshToken(ctx context.Context, tokenHash string, opts ...tokens.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := tokens.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	rt, exists := s.refreshTokens[tokenHash]
	if !exists || rt.tenantID != tenantID {
		return tokens.ErrRefreshTokenNotFound
	}

	delete(s.refreshTokens, tokenHash)

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
