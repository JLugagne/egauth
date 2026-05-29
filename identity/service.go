package identity

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/libauth/passwords"
	"github.com/google/uuid"
)

// Default lockout configuration values.
const (
	DefaultLockThreshold = 5
	DefaultLockDuration  = 15 * time.Minute
)

// Default verification-token lifetimes.
const (
	DefaultPasswordResetTTL     = time.Hour
	DefaultEmailVerificationTTL = 24 * time.Hour
	DefaultMagicLinkTTL         = 15 * time.Minute
)

// Service defines the business logic for user identity operations.
type Service interface {
	Register(ctx context.Context, email, password string, opts ...Option) (*User, error)
	Authenticate(ctx context.Context, provider, providerID, password string, opts ...Option) (*User, error)

	// RequestPasswordReset mints a password-reset token for the account owning email. To
	// avoid account enumeration it returns ("", nil, nil) when no such account exists, so the
	// caller can present an identical response either way. When a token is returned the user
	// is returned too, so the caller can deliver the token (e.g. via a Mailer).
	RequestPasswordReset(ctx context.Context, email string, opts ...Option) (token string, user *User, err error)

	// ResetPassword validates newPassword against the policy, then consumes the reset token
	// (single-use) and sets the new password, clearing any lockout.
	ResetPassword(ctx context.Context, token, newPassword string, opts ...Option) error

	// RequestEmailVerification mints an email-verification token for the given user.
	RequestEmailVerification(ctx context.Context, userID uuid.UUID, opts ...Option) (token string, err error)

	// VerifyEmail consumes an email-verification token and marks the user's email verified,
	// returning the updated user.
	VerifyEmail(ctx context.Context, token string, opts ...Option) (*User, error)

	// LinkOrCreateIdentity resolves the user behind an external (e.g. OAuth) identity: it
	// returns the existing user when (provider, providerID) is already linked, otherwise it
	// just-in-time provisions a new user+identity. It refuses to silently attach the identity
	// to a pre-existing account that merely shares the email (returns ErrEmailAlreadyExists),
	// since auto-linking by email is an account-takeover vector.
	LinkOrCreateIdentity(ctx context.Context, provider, providerID, email string, emailVerified bool, opts ...Option) (*User, error)

	// RequestMagicLink mints a passwordless login token for the account owning email and
	// returns it together with the user (for delivery, e.g. via a Mailer). Like
	// RequestPasswordReset it returns ("", nil, nil) for an unknown account to avoid
	// enumeration. It works for any account (including OAuth-only) since it grants a session
	// rather than touching a password.
	RequestMagicLink(ctx context.Context, email string, opts ...Option) (token string, user *User, err error)

	// LoginWithMagicLink consumes a magic-link token (single-use) and returns the user it
	// authenticates, so the caller can issue a session/token pair.
	LoginWithMagicLink(ctx context.Context, token string, opts ...Option) (*User, error)
}

type service struct {
	store                Store
	hasher               passwords.Hasher
	policy               passwords.Policy
	lockThreshold        int
	lockDuration         time.Duration
	passwordResetTTL     time.Duration
	emailVerificationTTL time.Duration
	magicLinkTTL         time.Duration
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

// WithPasswordResetTTL overrides how long a password-reset token stays valid.
func WithPasswordResetTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.passwordResetTTL = d }
}

// WithEmailVerificationTTL overrides how long an email-verification token stays valid.
func WithEmailVerificationTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.emailVerificationTTL = d }
}

// WithMagicLinkTTL overrides how long a magic-link login token stays valid.
func WithMagicLinkTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.magicLinkTTL = d }
}

// NewService creates a new identity Service. By default it enables account lockout
// after DefaultLockThreshold failed attempts for DefaultLockDuration.
func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy, opts ...ServiceOption) Service {
	s := &service{
		store:                store,
		hasher:               hasher,
		policy:               policy,
		lockThreshold:        DefaultLockThreshold,
		lockDuration:         DefaultLockDuration,
		passwordResetTTL:     DefaultPasswordResetTTL,
		emailVerificationTTL: DefaultEmailVerificationTTL,
		magicLinkTTL:         DefaultMagicLinkTTL,
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
		// The store has no cross-call transaction, so a failed AddIdentity would otherwise
		// leave an orphaned user that permanently blocks re-registration of this email
		// (the live-row unique index keeps matching it). Compensate by soft-deleting the
		// just-created user, which anonymizes its email and frees the slot. Best-effort.
		_ = s.store.DeleteUser(ctx, user.ID, opts...)
		return nil, err
	}

	return user, nil
}

// decoyHash performs a throwaway password hash to equalize timing on authentication
// failure paths where no real password hash is available (unknown user/identity, or an
// identity without a password). This prevents user enumeration via response-time analysis.
func (s *service) decoyHash(ctx context.Context, password string) {
	if s.hasher == nil {
		return
	}
	_, _ = s.hasher.Hash(ctx, password)
}

func (s *service) Authenticate(ctx context.Context, provider, providerID, password string, opts ...Option) (*User, error) {
	if provider == "password" {
		user, err := s.store.FindUserByEmail(ctx, providerID, opts...)
		if err != nil {
			// Constant-time: apply an equivalent hashing cost so an attacker cannot
			// distinguish a missing user from a wrong password by timing (PRD §108).
			s.decoyHash(ctx, password)
			return nil, ErrInvalidCredentials
		}

		ident, err := s.store.FindIdentityByProvider(ctx, provider, providerID, opts...)
		if err != nil {
			s.decoyHash(ctx, password)
			return nil, ErrInvalidCredentials
		}

		// If the account is currently locked, reject without comparing the password.
		if ident.LockedUntil != nil && ident.LockedUntil.After(time.Now()) {
			return nil, ErrAccountLocked
		}

		if ident.PasswordHash == nil {
			s.decoyHash(ctx, password)
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

// RequestPasswordReset mints a password-reset token for the account owning email.
func (s *service) RequestPasswordReset(ctx context.Context, email string, opts ...Option) (string, *User, error) {
	user, err := s.store.FindUserByEmail(ctx, email, opts...)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Do not reveal whether the account exists.
			return "", nil, nil
		}
		return "", nil, err
	}

	// Only an account that actually has a password can reset it. Minting a token for an
	// OAuth-only account would hand the holder a single-use token that ResetPassword can never
	// apply (no password identity), burning it for nothing. Stay uniform: behave as if the
	// account did not exist (no token, no error).
	idents, err := s.store.FindIdentitiesByUserID(ctx, user.ID, opts...)
	if err != nil {
		return "", nil, err
	}
	if !hasPasswordIdentity(idents) {
		return "", nil, nil
	}

	token, err := s.store.CreateVerificationToken(ctx, user.ID, KindPasswordReset, s.passwordResetTTL, nil, opts...)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// hasPasswordIdentity reports whether the user owns a "password" identity.
func hasPasswordIdentity(idents []*Identity) bool {
	for _, id := range idents {
		if id.Provider == "password" {
			return true
		}
	}
	return false
}

// consumeForLiveUser consumes a verification token of the given kind and returns the user it
// is bound to, REJECTING tokens whose account has since been soft-deleted/deactivated.
// FindUserByID deliberately still returns soft-deleted users (the store contract depends on
// that for inspection), so the liveness gate must live here: otherwise a token minted while
// the account was live could resurrect a deactivated account and grant it a session.
func (s *service) consumeForLiveUser(ctx context.Context, token, kind string, opts ...Option) (*User, []byte, error) {
	userID, metadata, err := s.store.ConsumeVerificationToken(ctx, token, kind, opts...)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.store.FindUserByID(ctx, userID, opts...)
	if err != nil {
		return nil, nil, err
	}
	if user.DeletedAt != nil {
		return nil, nil, ErrUserNotFound
	}
	return user, metadata, nil
}

// ResetPassword validates the new password, consumes the token and sets the password.
func (s *service) ResetPassword(ctx context.Context, token, newPassword string, opts ...Option) error {
	// Validate and hash BEFORE consuming, so a weak password or a hashing failure does not
	// burn a single-use token.
	if err := s.policy.Verify(ctx, newPassword); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, newPassword)
	if err != nil {
		return err
	}

	user, _, err := s.consumeForLiveUser(ctx, token, KindPasswordReset, opts...)
	if err != nil {
		return err
	}

	return s.store.UpdateIdentityPassword(ctx, user.ID, hash, opts...)
}

// RequestEmailVerification mints an email-verification token for the given user.
func (s *service) RequestEmailVerification(ctx context.Context, userID uuid.UUID, opts ...Option) (string, error) {
	return s.store.CreateVerificationToken(ctx, userID, KindEmailVerification, s.emailVerificationTTL, nil, opts...)
}

// VerifyEmail consumes an email-verification token and marks the email verified.
func (s *service) VerifyEmail(ctx context.Context, token string, opts ...Option) (*User, error) {
	user, _, err := s.consumeForLiveUser(ctx, token, KindEmailVerification, opts...)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user.EmailVerifiedAt = &now
	if err := s.store.UpdateUser(ctx, user, opts...); err != nil {
		return nil, err
	}
	return user, nil
}

// LinkOrCreateIdentity resolves the user behind an external identity, JIT-provisioning when
// the provider identity is unknown.
func (s *service) LinkOrCreateIdentity(ctx context.Context, provider, providerID, email string, emailVerified bool, opts ...Option) (*User, error) {
	// 1. Already linked? Return the owning user.
	ident, err := s.store.FindIdentityByProvider(ctx, provider, providerID, opts...)
	if err == nil {
		return s.store.FindUserByID(ctx, ident.UserID, opts...)
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		return nil, err
	}

	// 2. Not linked. Refuse to silently attach to a pre-existing account that shares the
	//    email — that would be an account-takeover vector. The application must drive
	//    explicit linking from an authenticated session instead.
	if email != "" {
		if _, ferr := s.store.FindUserByEmail(ctx, email, opts...); ferr == nil {
			return nil, ErrEmailAlreadyExists
		} else if !errors.Is(ferr, ErrUserNotFound) {
			return nil, ferr
		}
	}

	// 3. JIT-provision a new user and link the identity.
	user, err := s.store.CreateUser(ctx, email, opts...)
	if err != nil {
		return nil, err
	}
	if emailVerified {
		now := time.Now()
		user.EmailVerifiedAt = &now
		if err := s.store.UpdateUser(ctx, user, opts...); err != nil {
			return nil, err
		}
	}

	link := &Identity{
		UserID:     user.ID,
		Provider:   provider,
		ProviderID: providerID,
	}
	if err := s.store.AddIdentity(ctx, link, opts...); err != nil {
		// Compensate for the lack of a transaction: drop the just-provisioned user so a
		// failed link does not leave an orphan that blocks future provisioning of this
		// email. Best-effort.
		_ = s.store.DeleteUser(ctx, user.ID, opts...)
		return nil, err
	}
	return user, nil
}

// RequestMagicLink mints a passwordless login token for the account owning email.
func (s *service) RequestMagicLink(ctx context.Context, email string, opts ...Option) (string, *User, error) {
	user, err := s.store.FindUserByEmail(ctx, email, opts...)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", nil, nil // do not reveal whether the account exists
		}
		return "", nil, err
	}

	token, err := s.store.CreateVerificationToken(ctx, user.ID, KindMagicLink, s.magicLinkTTL, nil, opts...)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// LoginWithMagicLink consumes a magic-link token and returns the user it authenticates. A
// token for a since-deactivated account is rejected (ErrUserNotFound) so account suspension
// reliably revokes pending passwordless logins.
func (s *service) LoginWithMagicLink(ctx context.Context, token string, opts ...Option) (*User, error) {
	user, _, err := s.consumeForLiveUser(ctx, token, KindMagicLink, opts...)
	return user, err
}
