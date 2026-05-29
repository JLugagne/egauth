package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/libauth/identity"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of identity.Store.
type Store struct {
	mu         sync.RWMutex
	users      map[uuid.UUID]*identity.User
	identities map[uuid.UUID]*identity.Identity
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{
		users:      make(map[uuid.UUID]*identity.User),
		identities: make(map[uuid.UUID]*identity.Identity),
	}
}

// CreateUser creates a new user.
func (s *Store) CreateUser(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email && u.DeletedAt == nil {
			return nil, identity.ErrEmailAlreadyExists
		}
	}

	now := time.Now()
	user := &identity.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	uCopy := *user
	s.users[user.ID] = &uCopy

	res := *user
	return &res, nil
}

// FindUserByID finds a user by their ID.
func (s *Store) FindUserByID(ctx context.Context, id uuid.UUID, opts ...identity.Option) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	user, exists := s.users[id]
	if !exists || user.TenantID != tenantID {
		return nil, identity.ErrUserNotFound
	}

	uCopy := *user
	return &uCopy, nil
}

// FindUserByEmail finds a user by their email.
func (s *Store) FindUserByEmail(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			if u.DeletedAt != nil {
				continue
			}
			uCopy := *u
			return &uCopy, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

// UpdateUser updates an existing user.
func (s *Store) UpdateUser(ctx context.Context, user *identity.User, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	existing, exists := s.users[user.ID]
	if !exists || existing.TenantID != tenantID {
		return identity.ErrUserNotFound
	}

	if existing.Email != user.Email {
		for _, u := range s.users {
			if u.TenantID == tenantID && u.Email == user.Email && u.DeletedAt == nil && u.ID != user.ID {
				return identity.ErrEmailAlreadyExists
			}
		}
	}

	uCopy := *user
	uCopy.UpdatedAt = time.Now()
	s.users[user.ID] = &uCopy

	return nil
}

// DeleteUser performs a soft delete and anonymizes the email.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	existing, exists := s.users[id]
	if !exists || existing.TenantID != tenantID || existing.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	now := time.Now()
	existing.DeletedAt = &now
	existing.Email = uuid.New().String()
	existing.UpdatedAt = now

	for _, ident := range s.identities {
		if ident.UserID == id {
			ident.ProviderID = uuid.New().String()
		}
	}

	return nil
}

// AddIdentity adds an identity to a user.
func (s *Store) AddIdentity(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	user, exists := s.users[ident.UserID]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	for _, id := range s.identities {
		if id.TenantID == tenantID && id.Provider == ident.Provider && id.ProviderID == ident.ProviderID {
			return identity.ErrIdentityAlreadyExists
		}
	}

	now := time.Now()
	ident.ID = uuid.New()
	ident.TenantID = tenantID
	ident.CreatedAt = now
	ident.UpdatedAt = now

	idCopy := *ident
	s.identities[ident.ID] = &idCopy

	return nil
}

// FindIdentitiesByUserID returns all identities for a user.
func (s *Store) FindIdentitiesByUserID(ctx context.Context, userID uuid.UUID, opts ...identity.Option) ([]*identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	var res []*identity.Identity
	for _, id := range s.identities {
		if id.UserID == userID && id.TenantID == tenantID {
			idCopy := *id
			res = append(res, &idCopy)
		}
	}

	return res, nil
}

// FindIdentityByProvider finds an identity by its provider and provider ID.
func (s *Store) FindIdentityByProvider(ctx context.Context, provider, providerID string, opts ...identity.Option) (*identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	for _, id := range s.identities {
		if id.TenantID == tenantID && id.Provider == provider && id.ProviderID == providerID {
			idCopy := *id
			return &idCopy, nil
		}
	}

	return nil, identity.ErrIdentityNotFound
}

// IncrementFailedAttempts increments the failed-attempt counter for an identity,
// locking the account when the threshold is reached.
func (s *Store) IncrementFailedAttempts(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	ident, exists := s.identities[identityID]
	if !exists || ident.TenantID != tenantID {
		return identity.ErrIdentityNotFound
	}

	ident.FailedAttempts++
	ident.UpdatedAt = time.Now()
	if lockThreshold > 0 && ident.FailedAttempts >= lockThreshold {
		lockedUntil := time.Now().Add(lockDuration)
		ident.LockedUntil = &lockedUntil
	}

	return nil
}

// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
func (s *Store) ResetFailedAttempts(ctx context.Context, identityID uuid.UUID, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	tenantID := ""
	if opt.TenantID != nil {
		tenantID = *opt.TenantID
	}

	ident, exists := s.identities[identityID]
	if !exists || ident.TenantID != tenantID {
		return identity.ErrIdentityNotFound
	}

	ident.FailedAttempts = 0
	ident.LockedUntil = nil
	ident.UpdatedAt = time.Now()

	return nil
}
