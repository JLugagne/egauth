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
	mu                 sync.RWMutex
	users              map[uuid.UUID]*identity.User
	identities         map[uuid.UUID]*identity.Identity
	verificationTokens map[string]*identity.VerificationToken // keyed by selector
	strict             bool
}

// Option configures a Store.
type Option func(*Store)

// WithStrictTenancy makes every tenant-scoped operation require a non-empty tenant
// (identity.ErrTenantRequired otherwise). Off by default, where an empty tenant is the valid
// default single-tenant partition. Enable it in multi-tenant deployments so a forgotten
// WithTenant fails loudly instead of silently operating on the shared empty-tenant partition.
// (DeleteExpiredVerificationTokens is exempt: it is a maintenance sweep that intentionally
// spans all tenants when no tenant is given.)
func WithStrictTenancy() Option { return func(s *Store) { s.strict = true } }

// NewStore creates a new in-memory Store.
func NewStore(opts ...Option) *Store {
	s := &Store{
		users:              make(map[uuid.UUID]*identity.User),
		identities:         make(map[uuid.UUID]*identity.Identity),
		verificationTokens: make(map[string]*identity.VerificationToken),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveTenant extracts the operation tenant, enforcing ErrTenantRequired in strict mode.
func (s *Store) resolveTenant(opts []identity.Option) (string, error) {
	o := identity.ApplyOptions(opts)
	tenantID := ""
	if o.TenantID != nil {
		tenantID = *o.TenantID
	}
	if s.strict && tenantID == "" {
		return "", identity.ErrTenantRequired
	}
	return tenantID, nil
}

// CreateUser creates a new user.
func (s *Store) CreateUser(ctx context.Context, email string, opts ...identity.Option) (*identity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
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

// UpdateUserEmail atomically swaps a live user's email and re-keys its password identity.
func (s *Store) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string, verifiedAt time.Time, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}

	user, exists := s.users[userID]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	// Uniqueness: no other live user may already hold newEmail. Because a password identity is
	// keyed by its owner's email, a real conflict on the identity (provider, provider_id) index
	// is always accompanied by this live-user-email conflict, so checking the email alone matches
	// what the pgx backend enforces (its identity re-key only runs when the user owns a password
	// identity). Both backends therefore reject exactly the reachable taken-address cases.
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == newEmail && u.DeletedAt == nil && u.ID != userID {
			return identity.ErrEmailAlreadyExists
		}
	}

	now := time.Now()
	user.Email = newEmail
	v := verifiedAt
	user.EmailVerifiedAt = &v
	user.UpdatedAt = now
	for _, ident := range s.identities {
		if ident.UserID == userID && ident.TenantID == tenantID && ident.Provider == "password" {
			ident.ProviderID = newEmail
			ident.UpdatedAt = now
		}
	}

	return nil
}

// DeleteUser performs a soft delete and anonymizes the email.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
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
		if ident.UserID == id && ident.TenantID == tenantID {
			ident.ProviderID = uuid.New().String()
		}
	}

	// Purge any pending verification tokens for the user: they would otherwise outlive the
	// account, carrying its user_id and (for change-email tokens) a plaintext target email —
	// residual PII the soft delete is meant to erase. Deleting during range is safe in Go.
	for selector, vt := range s.verificationTokens {
		if vt.UserID == id && vt.TenantID == tenantID {
			delete(s.verificationTokens, selector)
		}
	}

	return nil
}

// AddIdentity adds an identity to a user.
func (s *Store) AddIdentity(ctx context.Context, ident *identity.Identity, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return nil, err
	}

	for _, id := range s.identities {
		if id.TenantID == tenantID && id.Provider == provider && id.ProviderID == providerID {
			idCopy := *id
			return &idCopy, nil
		}
	}

	return nil, identity.ErrIdentityNotFound
}

// UpdateIdentityPassword sets a new password hash on the user's "password" identity and
// clears any lockout.
func (s *Store) UpdateIdentityPassword(ctx context.Context, userID uuid.UUID, passwordHash string, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
	}

	for _, ident := range s.identities {
		if ident.UserID == userID && ident.TenantID == tenantID && ident.Provider == "password" {
			hash := passwordHash
			ident.PasswordHash = &hash
			ident.FailedAttempts = 0
			ident.LockedUntil = nil
			ident.UpdatedAt = time.Now()
			return nil
		}
	}

	return identity.ErrIdentityNotFound
}

// CreateVerificationToken mints, persists and returns a single-use plaintext token.
func (s *Store) CreateVerificationToken(ctx context.Context, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte, opts ...identity.Option) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return "", err
	}

	// Mirror the pgx foreign-key constraint: the user must exist (and be live) in the tenant.
	user, exists := s.users[userID]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return "", identity.ErrUserNotFound
	}

	token, selector, verifierHash, err := identity.GenerateVerificationToken()
	if err != nil {
		return "", err
	}

	now := time.Now()
	vt := &identity.VerificationToken{
		Selector:     selector,
		VerifierHash: verifierHash,
		UserID:       userID,
		TenantID:     tenantID,
		Kind:         kind,
		Metadata:     append([]byte(nil), metadata...),
		ExpiresAt:    now.Add(ttl),
		CreatedAt:    now,
	}
	s.verificationTokens[selector] = vt

	return token, nil
}

// ConsumeVerificationToken validates and atomically consumes a verification token.
func (s *Store) ConsumeVerificationToken(ctx context.Context, token, kind string, opts ...identity.Option) (uuid.UUID, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return uuid.Nil, nil, err
	}

	selector, verifier, ok := identity.SplitVerificationToken(token)
	if !ok {
		return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
	}

	vt, exists := s.verificationTokens[selector]
	// The verifier is always compared in constant time; selector lookup itself needs no
	// timing decoy because the selector is a 128-bit random value, not an enumerable key.
	if !exists || vt.TenantID != tenantID || vt.Kind != kind || !identity.CompareVerifier(vt.VerifierHash, verifier) {
		return uuid.Nil, nil, identity.ErrVerificationTokenNotFound
	}

	if time.Now().After(vt.ExpiresAt) {
		// Expired but genuine: drop it and report expiry to the legitimate holder.
		delete(s.verificationTokens, selector)
		return uuid.Nil, nil, identity.ErrVerificationTokenExpired
	}

	delete(s.verificationTokens, selector) // single-use
	return vt.UserID, vt.Metadata, nil
}

// DeleteExpiredVerificationTokens purges verification tokens past their expiry, returning the
// number deleted. With WithTenant it sweeps a single tenant, otherwise all.
func (s *Store) DeleteExpiredVerificationTokens(ctx context.Context, opts ...identity.Option) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	opt := identity.ApplyOptions(opts)
	now := time.Now()
	var deleted int64
	for selector, vt := range s.verificationTokens {
		if opt.TenantID != nil && vt.TenantID != *opt.TenantID {
			continue
		}
		if now.After(vt.ExpiresAt) {
			delete(s.verificationTokens, selector)
			deleted++
		}
	}
	return deleted, nil
}

// IncrementFailedAttempts increments the failed-attempt counter for an identity,
// locking the account when the threshold is reached.
func (s *Store) IncrementFailedAttempts(ctx context.Context, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration, opts ...identity.Option) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
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

	tenantID, err := s.resolveTenant(opts)
	if err != nil {
		return err
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
