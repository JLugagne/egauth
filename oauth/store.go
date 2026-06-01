package oauth

import (
	"context"
	"errors"
	"sync"
)

// ErrProviderNotFound is returned by a ProviderStore when the requested provider is not
// configured for the given tenant.
var ErrProviderNotFound = errors.New("oauth: provider not found")

// ProviderStore looks up an OAuth/OIDC provider dynamically for a specific tenant.
// It allows multi-tenant applications to use different SSO connections per tenant.
type ProviderStore interface {
	GetProvider(ctx context.Context, tenantID, providerName string) (*Provider, error)
}

// MemoryStore is a thread-safe, in-memory implementation of ProviderStore.
// It is useful for applications with static configurations or for testing.
type MemoryStore struct {
	mu        sync.RWMutex
	providers map[string]map[string]*Provider // tenantID -> providerName -> *Provider
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		providers: make(map[string]map[string]*Provider),
	}
}

// AddProvider registers a provider for a specific tenant.
// Passing an empty string for tenantID stores it in the single-tenant (global) partition.
func (m *MemoryStore) AddProvider(tenantID string, p *Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.providers[tenantID] == nil {
		m.providers[tenantID] = make(map[string]*Provider)
	}
	m.providers[tenantID][p.Name()] = p
}

// GetProvider retrieves a provider for a specific tenant.
func (m *MemoryStore) GetProvider(ctx context.Context, tenantID, providerName string) (*Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tenantProviders, ok := m.providers[tenantID]
	if !ok {
		return nil, ErrProviderNotFound
	}
	p, ok := tenantProviders[providerName]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return p, nil
}
