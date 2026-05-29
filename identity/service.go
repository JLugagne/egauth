package identity

import (
	"context"
	"time"

	"github.com/JLugagne/libauth/passwords"
)

// Default lockout configuration values.
const (
	DefaultLockThreshold = 5
	DefaultLockDuration  = 15 * time.Minute
)

// Service defines the business logic for user identity operations.
type Service interface {
	Register(ctx context.Context, email, password string, opts ...Option) (*User, error)
	Authenticate(ctx context.Context, provider, providerID, password string, opts ...Option) (*User, error)
}

type service struct {
	store         Store
	hasher        passwords.Hasher
	policy        passwords.Policy
	lockThreshold int
	lockDuration  time.Duration
}

// ServiceOption configures optional behavior of the identity Service.
type ServiceOption func(*service)

// WithLockout overrides the default account-lockout threshold and duration.
func WithLockout(threshold int, duration time.Duration) ServiceOption {
	return func(s *service) {
		s.lockThreshold = threshold
		s.lockDuration = duration
	}
}

// NewService creates a new identity Service. By default it enables account lockout
// after DefaultLockThreshold failed attempts for DefaultLockDuration.
func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy, opts ...ServiceOption) Service {
	s := &service{
		store:         store,
		hasher:        hasher,
		policy:        policy,
		lockThreshold: DefaultLockThreshold,
		lockDuration:  DefaultLockDuration,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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

		// If the account is currently locked, reject without comparing the password.
		if ident.LockedUntil != nil && ident.LockedUntil.After(time.Now()) {
			return nil, ErrAccountLocked
		}

		if ident.PasswordHash == nil {
			return nil, ErrInvalidCredentials
		}

		if err := s.hasher.Compare(ctx, *ident.PasswordHash, password); err != nil {
			// Record the failed attempt (and possibly lock the account).
			_ = s.store.IncrementFailedAttempts(ctx, ident.ID, s.lockThreshold, s.lockDuration, opts...)
			return nil, ErrInvalidCredentials
		}

		// Successful authentication: reset the counter only if there were prior attempts.
		if ident.FailedAttempts > 0 {
			_ = s.store.ResetFailedAttempts(ctx, ident.ID, opts...)
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
