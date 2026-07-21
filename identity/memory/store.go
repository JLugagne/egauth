package memory

import (
	"context"
	"sync"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/google/uuid"
)

// Store is an in-memory implementation of identity.Store.
type Store struct {
	mu                 sync.RWMutex
	users              map[uuid.UUID]*identity.User
	identities         map[uuid.UUID]*identity.Identity
	verificationTokens map[string]*identity.VerificationToken // keyed by selector
}

// NewStore creates a new in-memory Store.
func NewStore() *Store {
	return &Store{
		users:              make(map[uuid.UUID]*identity.User),
		identities:         make(map[uuid.UUID]*identity.Identity),
		verificationTokens: make(map[string]*identity.VerificationToken),
	}
}

// CreateUser creates a new user.
func (s *Store) CreateUser(ctx context.Context, tenantID string, email string) (*identity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email && u.DeletedAt == nil {
			return nil, identity.ErrEmailAlreadyExists
		}
	}

	now := time.Now()
	user := &identity.User{
		ID:        uuid.Must(uuid.NewV7()),
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
func (s *Store) FindUserByID(ctx context.Context, tenantID string, id uuid.UUID) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists || user.TenantID != tenantID {
		return nil, identity.ErrUserNotFound
	}

	uCopy := *user
	return &uCopy, nil
}

// FindUserByEmail finds a user by their email.
func (s *Store) FindUserByEmail(ctx context.Context, tenantID string, email string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
func (s *Store) UpdateUser(ctx context.Context, tenantID string, user *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.TenantID != "" && user.TenantID != tenantID {
		return identity.ErrTenantMismatch
	}

	existing, exists := s.users[user.ID]
	if !exists || existing.TenantID != tenantID {
		return identity.ErrUserNotFound
	}

	// Refuse to mutate a soft-deleted user, matching the pgx store's
	// "WHERE deleted_at IS NULL" gate. Without this check the memory store
	// would silently resurrect an anonymized account.
	if existing.DeletedAt != nil {
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
	uCopy.TenantID = tenantID
	uCopy.UpdatedAt = time.Now()
	s.users[user.ID] = &uCopy

	return nil
}

// UpdateUserEmail atomically swaps a live user's email and re-keys its password identity.
func (s *Store) UpdateUserEmail(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string, verifiedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

// DeleteUser performs a soft delete and anonymizes the user row plus any password-provider
// identity rows. Non-password (OAuth/OIDC) identity ProviderIDs are intentionally preserved so
// that the already-linked branch of LinkOrCreateIdentity can still resolve the identity and
// reach the DeletedAt guard in the service layer — without this, re-authenticating with the
// same OAuth credentials would JIT-provision a new account instead of being refused.
func (s *Store) DeleteUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.users[id]
	if !exists || existing.TenantID != tenantID || existing.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	now := time.Now()
	existing.DeletedAt = &now
	existing.Email = uuid.Must(uuid.NewV7()).String()
	existing.UpdatedAt = now

	for _, ident := range s.identities {
		if ident.UserID == id && ident.TenantID == tenantID {
			// Only anonymize password-provider identities: their ProviderID is the user's
			// email address, which is PII that must be erased. OAuth/OIDC ProviderIDs are
			// opaque external subject identifiers; keeping them intact lets the already-linked
			// branch of LinkOrCreateIdentity detect the deleted account and refuse it (via the
			// DeletedAt gate in the service) rather than silently provisioning a new account.
			if ident.Provider == "password" {
				ident.ProviderID = uuid.Must(uuid.NewV7()).String()
			}
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
func (s *Store) AddIdentity(ctx context.Context, tenantID string, ident *identity.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ident.TenantID != "" && ident.TenantID != tenantID {
		return identity.ErrTenantMismatch
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
	ident.ID = uuid.Must(uuid.NewV7())
	ident.TenantID = tenantID
	ident.CreatedAt = now
	ident.UpdatedAt = now

	idCopy := *ident
	s.identities[ident.ID] = &idCopy

	return nil
}

// FindIdentitiesByUserID returns all identities for a user.
func (s *Store) FindIdentitiesByUserID(ctx context.Context, tenantID string, userID uuid.UUID) ([]*identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
func (s *Store) FindIdentityByProvider(ctx context.Context, tenantID string, provider, providerID string) (*identity.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, id := range s.identities {
		if id.TenantID == tenantID && id.Provider == provider && id.ProviderID == providerID {
			idCopy := *id
			return &idCopy, nil
		}
	}

	return nil, identity.ErrIdentityNotFound
}

// UpdateIdentityPassword sets a new password hash on the user's "password" identity,
// clears any lockout, stamps PasswordChangedAt and sets the MustChangePassword flag.
func (s *Store) UpdateIdentityPassword(ctx context.Context, tenantID string, userID uuid.UUID, passwordHash string, changedAt time.Time, mustChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ident := range s.identities {
		if ident.UserID == userID && ident.TenantID == tenantID && ident.Provider == "password" {
			hash := passwordHash
			ident.PasswordHash = &hash
			ident.FailedAttempts = 0
			ident.LockedUntil = nil
			ident.PasswordChangedAt = changedAt
			ident.MustChangePassword = mustChange
			ident.UpdatedAt = time.Now()
			return nil
		}
	}

	return identity.ErrIdentityNotFound
}

// CreateVerificationToken mints, persists and returns a single-use plaintext token.
func (s *Store) CreateVerificationToken(ctx context.Context, tenantID string, userID uuid.UUID, kind string, ttl time.Duration, metadata []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
func (s *Store) ConsumeVerificationToken(ctx context.Context, tenantID string, token, kind string) (uuid.UUID, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

// DeleteExpiredVerificationTokens purges verification tokens past their expiry within the given
// tenant, returning the number deleted.
func (s *Store) DeleteExpiredVerificationTokens(ctx context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var deleted int64
	for selector, vt := range s.verificationTokens {
		if vt.TenantID != tenantID {
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
// locking the account when the threshold is reached. justLocked reports whether this
// call is the one that crossed the threshold (see the LockoutStore interface contract).
//
// When the identity's prior lock has already expired at entry (LockedUntil is set but not
// after now), the counter is reset to zero and LockedUntil cleared before the increment, so a
// new lockout cycle begins and re-crossing the threshold reports justLocked again.
func (s *Store) IncrementFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID, lockThreshold int, lockDuration time.Duration) (justLocked bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ident, exists := s.identities[identityID]
	if !exists || ident.TenantID != tenantID {
		return false, identity.ErrIdentityNotFound
	}

	now := time.Now()
	if ident.LockedUntil != nil && !ident.LockedUntil.After(now) {
		ident.FailedAttempts = 0
		ident.LockedUntil = nil
	}

	before := ident.FailedAttempts
	ident.FailedAttempts++
	ident.UpdatedAt = now
	if lockThreshold > 0 && ident.FailedAttempts >= lockThreshold {
		lockedUntil := now.Add(lockDuration)
		ident.LockedUntil = &lockedUntil
		justLocked = before < lockThreshold
	}

	return justLocked, nil
}

// ResetFailedAttempts zeroes the failed-attempt counter and clears LockedUntil.
func (s *Store) ResetFailedAttempts(ctx context.Context, tenantID string, identityID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ident, exists := s.identities[identityID]
	if !exists || ident.TenantID != tenantID {
		return identity.ErrIdentityNotFound
	}

	ident.FailedAttempts = 0
	ident.LockedUntil = nil
	ident.UpdatedAt = time.Now()

	return nil
}

// FindUserByPhone finds a live user by their normalized phone number.
func (s *Store) FindUserByPhone(ctx context.Context, tenantID string, phone string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.TenantID == tenantID && u.DeletedAt == nil && u.Phone != nil && *u.Phone == phone {
			uCopy := *u
			return &uCopy, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

// UpdateUserPhone atomically sets a live user's phone and marks it verified, enforcing
// per-tenant phone uniqueness across other live accounts.
func (s *Store) UpdateUserPhone(ctx context.Context, tenantID string, userID uuid.UUID, newPhone string, verifiedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	for _, u := range s.users {
		if u.TenantID == tenantID && u.DeletedAt == nil && u.ID != userID && u.Phone != nil && *u.Phone == newPhone {
			return identity.ErrPhoneAlreadyExists
		}
	}

	now := time.Now()
	p := newPhone
	user.Phone = &p
	v := verifiedAt
	user.PhoneVerifiedAt = &v
	user.UpdatedAt = now

	return nil
}

// UpdateUserRecoveryEmail sets a live user's recovery email and marks it verified. The recovery
// email is a secondary contact channel (not a login key), so it is not enforced unique.
func (s *Store) UpdateUserRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string, verifiedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	now := time.Now()
	r := recoveryEmail
	user.RecoveryEmail = &r
	v := verifiedAt
	user.RecoveryEmailVerifiedAt = &v
	user.UpdatedAt = now

	return nil
}

// DisableUser marks a live user as administratively disabled (reversible suspension). It is a
// no-op-success when the user is already disabled.
func (s *Store) DisableUser(ctx context.Context, tenantID string, id uuid.UUID, disabledAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	d := disabledAt
	user.DisabledAt = &d
	user.UpdatedAt = time.Now()

	return nil
}

// EnableUser clears a user's disabled state, re-activating an administratively disabled account.
// It is a no-op-success when the user is not currently disabled.
func (s *Store) EnableUser(ctx context.Context, tenantID string, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists || user.TenantID != tenantID || user.DeletedAt != nil {
		return identity.ErrUserNotFound
	}

	user.DisabledAt = nil
	user.UpdatedAt = time.Now()

	return nil
}
