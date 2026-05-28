package identity

import (
	"context"

	"github.com/JLugagne/libauth/passwords"
)

// Service defines the business logic for user identity operations.
type Service interface {
	Register(ctx context.Context, email, password string, opts ...Option) (*User, error)
	Authenticate(ctx context.Context, provider, providerID, password string, opts ...Option) (*User, error)
}

type service struct {
	store  Store
	hasher passwords.Hasher
	policy passwords.Policy
}

// NewService creates a new identity Service.
func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy) Service {
	return &service{
		store:  store,
		hasher: hasher,
		policy: policy,
	}
}

func (s *service) Register(ctx context.Context, email, password string, opts ...Option) (*User, error) {
	if err := s.policy.Verify(ctx, password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return nil, err
	}

	user, err := s.store.CreateUser(ctx, email, opts...)
	if err != nil {
		return nil, err
	}

	ident := &Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &hash,
	}
	if err := s.store.AddIdentity(ctx, ident, opts...); err != nil {
		// Ideally we would rollback user creation here in a real implementation
		// using a unit of work or similar, but for now we'll just return the error.
		return nil, err
	}

	return user, nil
}

func (s *service) Authenticate(ctx context.Context, provider, providerID, password string, opts ...Option) (*User, error) {
	if provider == "password" {
		user, err := s.store.FindUserByEmail(ctx, providerID, opts...)
		if err != nil {
			return nil, ErrInvalidCredentials
		}

		ident, err := s.store.FindIdentityByProvider(ctx, provider, providerID, opts...)
		if err != nil {
			return nil, ErrInvalidCredentials
		}

		if ident.PasswordHash == nil {
			return nil, ErrInvalidCredentials
		}

		if err := s.hasher.Compare(ctx, *ident.PasswordHash, password); err != nil {
			return nil, ErrInvalidCredentials
		}

		return user, nil
	}

	// Fallback for other providers (if any)
	ident, err := s.store.FindIdentityByProvider(ctx, provider, providerID, opts...)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	user, err := s.store.FindUserByID(ctx, ident.UserID, opts...)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
