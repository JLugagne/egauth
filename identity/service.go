package identity

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/passwords"
	"github.com/google/uuid"
)

// normalizeEmail validates an email against RFC 5322 and returns its canonical form (trimmed,
// lowercased). Because account uniqueness is byte-exact at the store, normalizing here means
// "User@Example.com" and "user@example.com" resolve to a single account — closing both a
// duplicate-account hazard and a pre-registration takeover of a victim's case-variant. The
// local part is lowercased too: although RFC 5321 permits case-sensitive local parts, virtually
// all providers treat them case-insensitively, so this is the safe, expected behavior.
func normalizeEmail(email string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(addr.Address), nil
}

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
	// DefaultEmailChangeTTL is the lifetime of a change-email confirmation token. It is kept
	// short (reset-class, not the longer email-verification window) because switching the
	// account's login address is a sensitive, takeover-relevant action.
	DefaultEmailChangeTTL = time.Hour
	// DefaultPhoneVerificationTTL is the lifetime of a phone-verification token. It is kept short
	// because SMS-delivered codes are expected to be entered promptly and a stale code is a
	// liability.
	DefaultPhoneVerificationTTL = 15 * time.Minute
	// DefaultRecoveryEmailTTL is the lifetime of a recovery-email enrollment token. It mirrors
	// the email-verification window since it is an emailed confirmation link.
	DefaultRecoveryEmailTTL = 24 * time.Hour
)

// Service defines the business logic for user identity operations.
//
// Every operation is scoped to a tenant via a mandatory tenantID argument. An empty string is a
// legal tenant key (the single-tenant default partition); it must still be passed explicitly.
type Service interface {
	Register(ctx context.Context, tenantID string, email, password string) (*User, error)
	Authenticate(ctx context.Context, tenantID string, provider, providerID, password string) (*User, error)
	// RequestPasswordReset mints a password-reset token for the account owning email. To
	// avoid account enumeration it returns ("", nil, nil) when no such account exists, so the
	// caller can present an identical response either way. When a token is returned the user
	// is returned too, so the caller can deliver the token (e.g. via a Mailer).
	RequestPasswordReset(ctx context.Context, tenantID string, email string) (token string, user *User, err error)
	// ResetPassword validates newPassword against the policy, then consumes the reset token
	// (single-use) and sets the new password, clearing any lockout.
	ResetPassword(ctx context.Context, tenantID string, token, newPassword string) error
	// RequestEmailVerification mints an email-verification token for the given user.
	RequestEmailVerification(ctx context.Context, tenantID string, userID uuid.UUID) (token string, err error)
	// VerifyEmail consumes an email-verification token and marks the user's email verified,
	// returning the updated user.
	VerifyEmail(ctx context.Context, tenantID string, token string) (*User, error)
	// LinkOrCreateIdentity resolves the user behind an external (e.g. OAuth) identity: it
	// returns the existing user when (provider, providerID) is already linked, otherwise it
	// just-in-time provisions a new user+identity. It refuses to silently attach the identity
	// to a pre-existing account that merely shares the email (returns ErrEmailAlreadyExists),
	// since auto-linking by email is an account-takeover vector.
	LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*User, error)
	// RequestMagicLink mints a passwordless login token for the account owning email and
	// returns it together with the user (for delivery, e.g. via a Mailer). Like
	// RequestPasswordReset it returns ("", nil, nil) for an unknown account to avoid
	// enumeration. It works for any account (including OAuth-only) since it grants a session
	// rather than touching a password.
	RequestMagicLink(ctx context.Context, tenantID string, email string) (token string, user *User, err error)
	// LoginWithMagicLink consumes a magic-link token (single-use) and returns the user it
	// authenticates, so the caller can issue a session/token pair.
	LoginWithMagicLink(ctx context.Context, tenantID string, token string) (*User, error)
	// ChangePassword re-verifies the user's current password and, on success, validates the
	// new password against the policy and replaces the stored hash. It is the authenticated
	// self-service counterpart to ResetPassword (which is token-gated). It returns
	// ErrInvalidCredentials when the current password is wrong or the account has no password
	// identity (e.g. OAuth-only), or a passwords.Policy error when the new password is
	// rejected. After a successful change the caller SHOULD revoke the user's other sessions
	// and refresh-token families (that is cross-module and left to the consumer).
	ChangePassword(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error
	// RequestEmailChange starts the authenticated change-email flow for userID. It validates
	// and normalizes newEmail, rejects an address already owned by another live account in the
	// tenant (ErrEmailAlreadyExists), and mints a single-use token bound to newEmail (carried
	// as the token's metadata). The token MUST be delivered to newEmail — confirming it proves
	// control of the new address before the swap, so a hijacked session cannot silently move
	// the account to an attacker-controlled address. It returns ErrInvalidEmail for a malformed
	// address and ErrUserNotFound for an unknown/soft-deleted/cross-tenant user.
	RequestEmailChange(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (token string, err error)
	// ConfirmEmailChange consumes a change-email token (single-use) and atomically switches the
	// owning user's email to the address the token was minted for, marking it verified (the
	// confirmation, delivered to the new address, proves control). It returns the updated user.
	// It returns ErrEmailAlreadyExists when the target was claimed by another account in the
	// interim and ErrUserNotFound when the account was deactivated after the token was issued.
	ConfirmEmailChange(ctx context.Context, tenantID string, token string) (*User, error)
	// RequestPhoneVerification starts the phone-verification flow for userID. It validates and
	// normalizes phone to E.164, rejects a number already owned by another live account in the
	// tenant (ErrPhoneAlreadyExists), and mints a single-use token bound to phone (carried as the
	// token's metadata). The token MUST be delivered to phone over SMS — confirming it proves
	// control of the number before it is set on the account. It returns ErrInvalidPhone for a
	// malformed number and ErrUserNotFound for an unknown/soft-deleted/cross-tenant user. This is
	// a lower-assurance contact channel (NIST SP 800-63B excludes SMS as an authentication
	// factor); the mfa module still does not accept SMS.
	RequestPhoneVerification(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (token string, err error)
	// ConfirmPhoneVerification consumes a phone-verification token (single-use) and atomically
	// sets the owning user's phone to the number the token was minted for, marking it verified
	// (the confirmation, delivered to that number, proves control). It returns the updated user.
	// It returns ErrPhoneAlreadyExists when the number was claimed by another account in the
	// interim and ErrUserNotFound when the account was deactivated after the token was issued.
	ConfirmPhoneVerification(ctx context.Context, tenantID string, token string) (*User, error)
	// RequestRecoveryEmail starts enrollment of an INDEPENDENT recovery email for userID — a
	// secondary address, distinct from the primary login email, used as an account-recovery
	// channel. It validates and normalizes recoveryEmail, rejects it when it equals the account's
	// primary email (ErrRecoveryEmailIsPrimary — a recovery channel must be independent), and
	// mints a single-use token bound to recoveryEmail (carried as the token's metadata). The token
	// MUST be delivered to recoveryEmail — confirming it proves control of the recovery channel
	// before it is trusted. It returns ErrInvalidEmail for a malformed address and ErrUserNotFound
	// for an unknown/soft-deleted/cross-tenant user.
	RequestRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (token string, err error)
	// ConfirmRecoveryEmail consumes a recovery-email enrollment token (single-use) and sets the
	// owning user's recovery email to the address the token was minted for, marking it verified.
	// It returns the updated user, or ErrUserNotFound when the account was deactivated after the
	// token was issued.
	ConfirmRecoveryEmail(ctx context.Context, tenantID string, token string) (*User, error)
	// RecoveryChannels reports which INDEPENDENT verified recovery channels userID has enrolled
	// (a verified recovery email and/or a verified phone). It is the gate primitive for
	// sensitive recovery/factor-reset: a consumer requires RecoveryChannels(...).Any() (plus a
	// freshness/step-up check, see tokens.WithMaxAuthAge) before allowing such an operation. It
	// returns ErrUserNotFound for an unknown/soft-deleted/cross-tenant user.
	RecoveryChannels(ctx context.Context, tenantID string, userID uuid.UUID) (RecoveryChannels, error)
	// RequestPasswordResetViaRecovery mints a password-reset token for the account owning email
	// but, unlike RequestPasswordReset, directs it to a VERIFIED INDEPENDENT recovery channel
	// (recovery email or phone) rather than the primary inbox — so a compromised primary mailbox
	// cannot drive the reset. Like RequestPasswordReset it is enumeration-safe: it returns
	// ("", nil, RecoveryChannels{}, nil) for an unknown account OR for a known account with no
	// verified recovery channel, so the caller presents an identical response either way. When a
	// token is returned, the user and the available channels are returned too so the caller can
	// deliver the token to the recovery email and/or phone.
	RequestPasswordResetViaRecovery(ctx context.Context, tenantID string, email string) (token string, user *User, channels RecoveryChannels, err error)
	// DeleteAccount performs a user-facing account deletion: it revokes the user's cross-module
	// artifacts by running every registered AccountEraser (sessions, refresh-token families,
	// MFA, passkeys — see WithAccountErasers) and then soft-deletes and anonymizes the identity
	// (clearing the email and provider IDs, which erases the account's PII and frees its
	// email/identity slots for re-registration). Erasers run first so a revocation failure
	// aborts before anything is deleted, leaving the operation cleanly retriable; the identity
	// is soft-deleted only once every eraser succeeds. Returns ErrUserNotFound when no live user
	// matches. Deletion is sensitive and irreversible: callers SHOULD gate it behind a
	// re-authentication / step-up check (fresh proof of presence) in addition to the session —
	// this is a stronger bar than the ambient session alone, matching how ChangePassword
	// re-verifies the current password. Enforce it by wrapping DeleteAccountHandler's route with
	// tokens.RequireAuth(..., tokens.WithMaxAuthAge(d)): the auth_time freshness gate works for
	// any factor, so it also covers OAuth-only accounts that cannot re-verify a password.
	DeleteAccount(ctx context.Context, tenantID string, userID uuid.UUID) error
	// DisableUser administratively suspends an account: it sets the user's DisabledAt so subsequent
	// authentication is refused (Authenticate returns ErrAccountDisabled) and pending token-gated
	// actions, including magic-link logins, are revoked. It is REVERSIBLE — the row, email slot and
	// all data are retained — and is the counterpart to EnableUser. Disabling an already-disabled
	// account succeeds (idempotent). Unlike DeleteAccount it does NOT run the AccountErasers, so
	// existing sessions/refresh tokens are not revoked by this call; a caller that wants active
	// sessions terminated on suspension SHOULD revoke them separately. Returns ErrUserNotFound for
	// an unknown, soft-deleted or cross-tenant user. This is an administrative operation; gate it
	// behind appropriate authorization (it is not a self-service action).
	DisableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
	// EnableUser re-activates an administratively disabled account by clearing its DisabledAt.
	// Enabling an account that is not disabled succeeds (idempotent). Returns ErrUserNotFound for an
	// unknown, soft-deleted or cross-tenant user. This is an administrative operation; gate it behind
	// appropriate authorization.
	EnableUser(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// AccountEraser revokes one class of a user's cross-module artifacts (e.g. active sessions,
// refresh-token families, MFA enrollments, passkeys) as part of DeleteAccount. egauth keeps
// its modules decoupled — the identity service cannot reach the sessions/tokens/mfa/passkey
// stores itself — so account deletion runs whatever erasers the application registers via
// WithAccountErasers. Each eraser SHOULD be idempotent, since deletion may be retried after a
// partial failure.
type AccountEraser func(ctx context.Context, tenantID string, userID uuid.UUID) error

type service struct {
	store                Store
	hasher               passwords.Hasher
	policy               passwords.Policy
	lockThreshold        int
	lockDuration         time.Duration
	passwordResetTTL     time.Duration
	emailVerificationTTL time.Duration
	magicLinkTTL         time.Duration
	emailChangeTTL       time.Duration
	phoneVerificationTTL time.Duration
	recoveryEmailTTL     time.Duration
	erasers              []AccountEraser
	events               event.Sink
	now                  func() time.Time
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

// WithEmailChangeTTL overrides how long a change-email confirmation token stays valid.
func WithEmailChangeTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.emailChangeTTL = d }
}

// WithPhoneVerificationTTL overrides how long a phone-verification token stays valid.
func WithPhoneVerificationTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.phoneVerificationTTL = d }
}

// WithRecoveryEmailTTL overrides how long a recovery-email enrollment token stays valid.
func WithRecoveryEmailTTL(d time.Duration) ServiceOption {
	return func(s *service) { s.recoveryEmailTTL = d }
}

// WithAccountErasers registers cross-module revocation hooks run by DeleteAccount, in the order
// given, to revoke the deleted user's sessions, refresh-token families, MFA enrollments,
// passkeys, etc. egauth keeps its modules decoupled, so the identity service cannot revoke
// those itself; wire your other modules' revocation here. Erasers SHOULD be idempotent.
func WithAccountErasers(erasers ...AccountEraser) ServiceOption {
	return func(s *service) { s.erasers = append(s.erasers, erasers...) }
}

// WithEventSink registers a security-event sink (see the event package) that receives login
// success/failure, lockout, registration, password/email change, verification, magic-link login
// and account-deletion events. It is optional; without it no events are emitted.
func WithEventSink(sink event.Sink) ServiceOption {
	return func(s *service) { s.events = sink }
}

// WithClock overrides the time source used for the account-lockout gate and for the
// EmailVerifiedAt/UpdatedAt stamps written on email change and OAuth provisioning (primarily
// for tests). A nil clock is ignored; NewService falls back to time.Now. Note the lockout
// STAMP (LockedUntil = now + lockDuration) is computed by the Store, not the service, so it
// is not affected by this clock.
func WithClock(now func() time.Time) ServiceOption {
	return func(s *service) { s.now = now }
}

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *service) emit(ctx context.Context, e event.Event) {
	event.Emit(ctx, s.events, e)
}

// NewService creates a new identity Service. By default it enables account lockout after
// DefaultLockThreshold failed attempts for DefaultLockDuration. It panics on a nil store (always
// required) to fail fast at startup rather than with a nil-pointer panic deep in a request.
//
// The hasher and policy may be nil for a deployment that uses no password flows (e.g. OAuth-only);
// the OAuth/magic-link paths and the constant-time decoy hashing tolerate their absence. The
// password operations Register, ResetPassword and ChangePassword do require them, but a nil policy
// or hasher is NOT a constructor panic: those operations instead fail fast by returning
// ErrPasswordPolicyRequired (when policy is nil) or ErrPasswordHasherRequired (when hasher is nil)
// before touching the store, rather than panicking with a nil-pointer dereference inside the
// request. Authenticate with a nil hasher cannot succeed (no password can match) but is not a
// panic: it returns ErrInvalidCredentials via the decoy-hash path.
func NewService(store Store, hasher passwords.Hasher, policy passwords.Policy, opts ...ServiceOption) Service {
	if store == nil {
		panic("identity: NewService requires a non-nil Store")
	}
	s := &service{
		store:                store,
		hasher:               hasher,
		policy:               policy,
		lockThreshold:        DefaultLockThreshold,
		lockDuration:         DefaultLockDuration,
		passwordResetTTL:     DefaultPasswordResetTTL,
		emailVerificationTTL: DefaultEmailVerificationTTL,
		magicLinkTTL:         DefaultMagicLinkTTL,
		emailChangeTTL:       DefaultEmailChangeTTL,
		phoneVerificationTTL: DefaultPhoneVerificationTTL,
		recoveryEmailTTL:     DefaultRecoveryEmailTTL,
		now:                  time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s

}

func (s *service) Register(ctx context.Context, tenantID string, email, password string) (*User, error) {
	// A nil policy/hasher is legal (OAuth-only deployments) but a password operation cannot run
	// without them: fail fast with a clear error rather than dereference a nil deep in the request.
	if err := s.requirePasswordDeps(); err != nil {
		return nil, err
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}
	if err := s.policy.Verify(ctx, password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return nil, err
	}

	user, err := s.store.CreateUser(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}

	ident := &Identity{
		UserID:       user.ID,
		Provider:     "password",
		ProviderID:   email,
		PasswordHash: &hash,
	}
	if err := s.store.AddIdentity(ctx, tenantID, ident); err != nil {
		// The store has no cross-call transaction, so a failed AddIdentity would otherwise
		// leave an orphaned user that permanently blocks re-registration of this email
		// (the live-row unique index keeps matching it). Compensate by soft-deleting the
		// just-created user, which anonymizes its email and frees the slot. Best-effort.
		_ = s.store.DeleteUser(ctx, tenantID, user.ID)
		return nil, err
	}

	s.emit(ctx, event.Event{Type: event.UserRegistered, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// requirePasswordDeps reports whether the password-flow dependencies are present. A nil policy or
// hasher is legal for an OAuth-only deployment (see NewService), but the password operations
// (Register/ResetPassword/ChangePassword) cannot run without them. Calling it at the top of those
// operations turns a forgotten dependency into a clear, fail-fast error
// (ErrPasswordPolicyRequired / ErrPasswordHasherRequired) instead of a nil-pointer panic deep in
// the request. The policy is checked first because it is the first dependency those operations use.
func (s *service) requirePasswordDeps() error {
	if s.policy == nil {
		return ErrPasswordPolicyRequired
	}
	if s.hasher == nil {
		return ErrPasswordHasherRequired
	}
	return nil
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

func (s *service) Authenticate(ctx context.Context, tenantID string, provider, providerID, password string) (*User, error) {
	// loginFailed emits a uniform failure event. UserID is "" on the enumeration-safe paths
	// (unknown account) where no user is resolved; the reason is deliberately uniform there so
	// the audit log mirrors the uniform client response and is not itself an enumeration oracle.
	loginFailed := func(userID, reason string) {
		s.emit(ctx, event.Event{Type: event.LoginFailed, UserID: userID, TenantID: tenantID, Reason: reason})
	}

	if provider == "password" {
		normalized, nerr := normalizeEmail(providerID)
		if nerr != nil {
			// Not a valid email: spend an equivalent hashing cost, then fail uniformly so a
			// malformed identifier is indistinguishable from a wrong password.
			s.decoyHash(ctx, password)
			loginFailed("", "invalid_credentials")
			return nil, ErrInvalidCredentials
		}
		providerID = normalized

		user, err := s.store.FindUserByEmail(ctx, tenantID, providerID)
		if err != nil {
			// Constant-time: apply an equivalent hashing cost so an attacker cannot
			// distinguish a missing user from a wrong password by timing (PRD §108).
			s.decoyHash(ctx, password)
			loginFailed("", "invalid_credentials")
			return nil, ErrInvalidCredentials
		}

		ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
		if err != nil {
			s.decoyHash(ctx, password)
			loginFailed(user.ID.String(), "invalid_credentials")
			return nil, ErrInvalidCredentials
		}

		// If the account is currently locked, reject without comparing the password.
		if ident.LockedUntil != nil && ident.LockedUntil.After(s.now()) {
			loginFailed(user.ID.String(), "account_locked")
			return nil, ErrAccountLocked
		}

		// An administratively disabled account is rejected without comparing the password, like a
		// lockout. Unlike a lockout it does not clear on its own; only EnableUser re-activates it.
		if user.DisabledAt != nil {
			loginFailed(user.ID.String(), "account_disabled")
			return nil, ErrAccountDisabled
		}

		if ident.PasswordHash == nil {
			s.decoyHash(ctx, password)
			loginFailed(user.ID.String(), "invalid_credentials")
			return nil, ErrInvalidCredentials
		}

		if err := s.hasher.Compare(ctx, *ident.PasswordHash, password); err != nil {
			// Record the failed attempt (and possibly lock the account). The error is not
			// propagated (the response stays uniform) but it gates the lockout event below.
			incErr := s.store.IncrementFailedAttempts(ctx, tenantID, ident.ID, s.lockThreshold, s.lockDuration)
			loginFailed(user.ID.String(), "invalid_credentials")
			// Surface the lockout as its own event — but only when the store actually persisted
			// the attempt that crosses the threshold. Emitting on a pre-increment prediction even
			// when the store call errored would assert a lock that never took effect, misleading a
			// SIEM/audit consumer. (ident.FailedAttempts is the pre-increment count, so +1 is the
			// value the store would persist; it matches both backends' lock condition.)
			if incErr == nil && s.lockThreshold > 0 && ident.FailedAttempts+1 >= s.lockThreshold {
				s.emit(ctx, event.Event{Type: event.AccountLocked, UserID: user.ID.String(), TenantID: tenantID})
			}
			return nil, ErrInvalidCredentials
		}

		// Successful authentication: reset the counter only if there were prior attempts.
		if ident.FailedAttempts > 0 {
			_ = s.store.ResetFailedAttempts(ctx, tenantID, ident.ID)
		}

		s.emit(ctx, event.Event{Type: event.LoginSucceeded, UserID: user.ID.String(), TenantID: tenantID})
		return user, nil
	}

	// Fallback for other providers (if any)
	ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
	if err != nil {
		loginFailed("", "invalid_credentials")
		return nil, ErrInvalidCredentials
	}

	user, err := s.store.FindUserByID(ctx, tenantID, ident.UserID)
	if err != nil {
		loginFailed("", "invalid_credentials")
		return nil, ErrInvalidCredentials
	}

	// A disabled account cannot authenticate via any provider.
	if user.DisabledAt != nil {
		loginFailed(user.ID.String(), "account_disabled")
		return nil, ErrAccountDisabled
	}

	s.emit(ctx, event.Event{Type: event.LoginSucceeded, UserID: user.ID.String(), TenantID: tenantID})
	return user, nil
}

// RequestPasswordReset mints a password-reset token for the account owning email.
func (s *service) RequestPasswordReset(ctx context.Context, tenantID string, email string) (string, *User, error) {
	email, nerr := normalizeEmail(email)
	if nerr != nil {
		// Stay uniform: a malformed email behaves exactly like an unknown account.
		return "", nil, nil
	}
	user, err := s.store.FindUserByEmail(ctx, tenantID, email)
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
	idents, err := s.store.FindIdentitiesByUserID(ctx, tenantID, user.ID)
	if err != nil {
		return "", nil, err
	}
	if !hasPasswordIdentity(idents) {
		return "", nil, nil
	}

	token, err := s.store.CreateVerificationToken(ctx, tenantID, user.ID, KindPasswordReset, s.passwordResetTTL, nil)
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
// DeleteUser purges a user's pending tokens, so in practice a token for a deactivated account
// is already gone (ConsumeVerificationToken returns ErrVerificationTokenNotFound first). This
// liveness gate remains as belt-and-suspenders: FindUserByID deliberately still returns
// soft-deleted users (the store contract depends on that for inspection), so should any token
// ever outlive its account, it still cannot resurrect a deactivated account or grant a session.
func (s *service) consumeForLiveUser(ctx context.Context, tenantID string, token, kind string) (*User, []byte, error) {
	userID, metadata, err := s.store.ConsumeVerificationToken(ctx, tenantID, token, kind)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return nil, nil, err
	}
	if user.DeletedAt != nil {
		return nil, nil, ErrUserNotFound
	}
	// A disabled (administratively suspended) account cannot consume verification tokens: this
	// reliably revokes a pending magic-link login, email-change or other token-gated action while
	// the suspension is in force. ErrUserNotFound keeps the response indistinguishable from an
	// account that no longer exists.
	if user.DisabledAt != nil {
		return nil, nil, ErrUserNotFound
	}
	return user, metadata, nil
}

// ResetPassword validates the new password, consumes the token and sets the password.
func (s *service) ResetPassword(ctx context.Context, tenantID string, token, newPassword string) error {
	// A nil policy/hasher is legal (OAuth-only deployments) but a password operation cannot run
	// without them: fail fast with a clear error rather than dereference a nil deep in the request.
	if err := s.requirePasswordDeps(); err != nil {
		return err
	}
	// Validate and hash BEFORE consuming, so a weak password or a hashing failure does not
	// burn a single-use token.
	if err := s.policy.Verify(ctx, newPassword); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, newPassword)
	if err != nil {
		return err
	}

	user, _, err := s.consumeForLiveUser(ctx, tenantID, token, KindPasswordReset)
	if err != nil {
		return err
	}

	if err := s.store.UpdateIdentityPassword(ctx, tenantID, user.ID, hash); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.PasswordReset, UserID: user.ID.String(), TenantID: user.TenantID})
	return nil
}

// ChangePassword re-verifies the user's current password, then validates and applies a new one.
func (s *service) ChangePassword(ctx context.Context, tenantID string, userID uuid.UUID, currentPassword, newPassword string) error {
	// A nil policy/hasher is legal (OAuth-only deployments) but a password operation cannot run
	// without them: fail fast with a clear error rather than dereference a nil deep in the request.
	if err := s.requirePasswordDeps(); err != nil {
		return err
	}
	// Validate the new password against the policy first: a weak new password must fail fast,
	// before we spend a KDF comparison on the current credential or touch the store.
	if err := s.policy.Verify(ctx, newPassword); err != nil {
		return err
	}

	idents, err := s.store.FindIdentitiesByUserID(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	var pwIdent *Identity
	for _, id := range idents {
		if id.Provider == "password" && id.PasswordHash != nil {
			pwIdent = id
			break
		}
	}
	if pwIdent == nil {
		// No password set (e.g. an OAuth-only account). Apply an equivalent hashing cost so the
		// response time does not distinguish "no password" from "wrong password".
		s.decoyHash(ctx, currentPassword)
		return ErrInvalidCredentials
	}

	if err := s.hasher.Compare(ctx, *pwIdent.PasswordHash, currentPassword); err != nil {
		return ErrInvalidCredentials
	}

	hash, err := s.hasher.Hash(ctx, newPassword)
	if err != nil {
		return err
	}
	if err := s.store.UpdateIdentityPassword(ctx, tenantID, userID, hash); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.PasswordChanged, UserID: userID.String(), TenantID: tenantID})
	return nil
}

// RequestEmailChange mints a token that, once confirmed, switches userID's email to newEmail.
func (s *service) RequestEmailChange(ctx context.Context, tenantID string, userID uuid.UUID, newEmail string) (string, error) {
	newEmail, err := normalizeEmail(newEmail)
	if err != nil {
		return "", err
	}

	// Pre-flight uniqueness check: reject up front when another live account in the tenant
	// already owns the address (consistent with registration's email_taken behavior). This is
	// only advisory — the store's unique index is the authoritative guard at confirm time, which
	// closes the request→confirm race. Finding the *same* user (newEmail is already theirs) is
	// not a conflict; confirming would simply re-verify it.
	if existing, ferr := s.store.FindUserByEmail(ctx, tenantID, newEmail); ferr == nil {
		if existing.ID != userID {
			return "", ErrEmailAlreadyExists
		}
	} else if !errors.Is(ferr, ErrUserNotFound) {
		return "", ferr
	}

	// Bind the requested address to the token as metadata. CreateVerificationToken also gates
	// on userID being a live, same-tenant account (returning ErrUserNotFound otherwise).
	token, err := s.store.CreateVerificationToken(ctx, tenantID, userID, KindEmailChange, s.emailChangeTTL, []byte(newEmail))
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmEmailChange consumes a change-email token and atomically applies the new address.
func (s *service) ConfirmEmailChange(ctx context.Context, tenantID string, token string) (*User, error) {
	user, metadata, err := s.consumeForLiveUser(ctx, tenantID, token, KindEmailChange)
	if err != nil {
		return nil, err
	}

	// The token carries the (already-normalized) new address. Re-normalize defensively rather
	// than trusting stored bytes blindly.
	newEmail, err := normalizeEmail(string(metadata))
	if err != nil {
		return nil, err
	}

	now := s.now()
	// UpdateUserEmail is the atomic swap point: it switches the user email AND re-keys the
	// password identity (which is keyed by email) in one operation, enforcing email uniqueness,
	// so a target claimed since the token was minted yields ErrEmailAlreadyExists rather than a
	// duplicate live email or a password identity left stranded on the old address. Confirming a
	// token delivered to the new address proves control of it, so the address is marked verified.
	if err := s.store.UpdateUserEmail(ctx, tenantID, user.ID, newEmail, now); err != nil {
		return nil, err
	}
	// Reflect the post-swap state on the returned user (it was loaded pre-swap).
	user.Email = newEmail
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now
	s.emit(ctx, event.Event{Type: event.EmailChanged, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// DeleteAccount revokes the user's cross-module artifacts, then soft-deletes the identity.
func (s *service) DeleteAccount(ctx context.Context, tenantID string, userID uuid.UUID) error {
	// Gate on a live, same-tenant user first so we report ErrUserNotFound (and skip the erasers)
	// for an unknown, soft-deleted or cross-tenant account.
	user, err := s.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if user.DeletedAt != nil {
		return ErrUserNotFound
	}

	// Run the cross-module erasers before touching the identity: a revocation failure must abort
	// cleanly (the account stays live and the whole operation can be retried) rather than leave
	// an erased identity with still-live sessions. Collect every eraser's error so one failure
	// does not mask another.
	var errs []error
	for _, erase := range s.erasers {
		if erase == nil {
			continue
		}
		// Honor cancellation between erasers (this is a multi-step cross-module cascade): if the
		// context is done, abort before running another eraser and before the soft-delete, so a
		// cancelled deletion leaves the account live and cleanly retriable.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := erase(ctx, tenantID, userID); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.store.DeleteUser(ctx, tenantID, userID); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.AccountDeleted, UserID: userID.String(), TenantID: user.TenantID})
	return nil
}

// RequestEmailVerification mints an email-verification token for the given user. Like the
// other Request* flows it is enumeration-safe: a non-existent, soft-deleted or cross-tenant
// user yields ("", nil) rather than a distinct error, so a caller cannot use the 500-vs-204
// (or latency) difference as an oracle for whether a userID is a live, same-tenant account.
func (s *service) RequestEmailVerification(ctx context.Context, tenantID string, userID uuid.UUID) (string, error) {
	token, err := s.store.CreateVerificationToken(ctx, tenantID, userID, KindEmailVerification, s.emailVerificationTTL, nil)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", nil
		}
		return "", err
	}
	return token, nil
}

// VerifyEmail consumes an email-verification token and marks the email verified.
func (s *service) VerifyEmail(ctx context.Context, tenantID string, token string) (*User, error) {
	user, _, err := s.consumeForLiveUser(ctx, tenantID, token, KindEmailVerification)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user.EmailVerifiedAt = &now
	if err := s.store.UpdateUser(ctx, tenantID, user); err != nil {
		return nil, err
	}
	s.emit(ctx, event.Event{Type: event.EmailVerified, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// LinkOrCreateIdentity resolves the user behind an external identity, JIT-provisioning when
// the provider identity is unknown.
func (s *service) LinkOrCreateIdentity(ctx context.Context, tenantID string, provider, providerID, email string, emailVerified bool) (*User, error) {
	// Canonicalize the provider-supplied email so the takeover-by-email guard and account
	// linking compare on the same normalized form the password flow stores. An unparseable
	// value is dropped (provision without an email) rather than persisted verbatim.
	if email != "" {
		if normalized, nerr := normalizeEmail(email); nerr == nil {
			email = normalized
		} else {
			email = ""
		}
	}

	// 1. Already linked? Return the owning user.
	ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
	if err == nil {
		return s.store.FindUserByID(ctx, tenantID, ident.UserID)
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		return nil, err
	}

	// 2. Not linked. Refuse to silently attach to a pre-existing account that shares the
	//    email — that would be an account-takeover vector. The application must drive
	//    explicit linking from an authenticated session instead.
	if email != "" {
		if _, ferr := s.store.FindUserByEmail(ctx, tenantID, email); ferr == nil {
			return nil, ErrEmailAlreadyExists
		} else if !errors.Is(ferr, ErrUserNotFound) {
			return nil, ferr
		}
	}

	// 3. JIT-provision a new user and link the identity.
	user, err := s.store.CreateUser(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	if emailVerified {
		now := s.now()
		user.EmailVerifiedAt = &now
		if err := s.store.UpdateUser(ctx, tenantID, user); err != nil {
			return nil, err
		}
	}

	link := &Identity{
		UserID:     user.ID,
		Provider:   provider,
		ProviderID: providerID,
	}
	if err := s.store.AddIdentity(ctx, tenantID, link); err != nil {
		// Compensate for the lack of a transaction: drop the just-provisioned user so a
		// failed link does not leave an orphan that blocks future provisioning of this
		// email. Best-effort.
		_ = s.store.DeleteUser(ctx, tenantID, user.ID)
		return nil, err
	}
	return user, nil
}

// RequestMagicLink mints a passwordless login token for the account owning email.
func (s *service) RequestMagicLink(ctx context.Context, tenantID string, email string) (string, *User, error) {
	email, nerr := normalizeEmail(email)
	if nerr != nil {
		// Stay uniform: a malformed email behaves exactly like an unknown account.
		return "", nil, nil
	}
	user, err := s.store.FindUserByEmail(ctx, tenantID, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", nil, nil // do not reveal whether the account exists
		}
		return "", nil, err
	}

	token, err := s.store.CreateVerificationToken(ctx, tenantID, user.ID, KindMagicLink, s.magicLinkTTL, nil)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// LoginWithMagicLink consumes a magic-link token and returns the user it authenticates. A
// token for a since-deactivated account is rejected (ErrUserNotFound) so account suspension
// reliably revokes pending passwordless logins.
func (s *service) LoginWithMagicLink(ctx context.Context, tenantID string, token string) (*User, error) {
	user, _, err := s.consumeForLiveUser(ctx, tenantID, token, KindMagicLink)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, event.Event{Type: event.MagicLinkLogin, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// normalizePhone validates a phone number and returns its canonical E.164 form. It strips the
// common human-formatting characters (spaces, dashes, parentheses, and dots) and then requires a
// leading '+' followed by 8 to 15 digits, the E.164 range. egauth deliberately does NOT do
// region-aware parsing or carrier lookup (that needs a heavyweight dependency and live data); the
// goal is a cheap, dependency-free sanity check so uniqueness and delivery operate on a canonical
// string. Callers that need stricter validation can normalize upstream and pass an E.164 number.
func normalizePhone(phone string) (string, error) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(phone) {
		switch r {
		case ' ', '-', '(', ')', '.':
			continue
		default:
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if len(cleaned) < 2 || cleaned[0] != '+' {
		return "", ErrInvalidPhone
	}
	digits := cleaned[1:]
	if len(digits) < 8 || len(digits) > 15 {
		return "", ErrInvalidPhone
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", ErrInvalidPhone
		}
	}
	return cleaned, nil
}

// RequestPhoneVerification mints a token that, once confirmed, sets userID's phone to phone.
func (s *service) RequestPhoneVerification(ctx context.Context, tenantID string, userID uuid.UUID, phone string) (string, error) {
	phone, err := normalizePhone(phone)
	if err != nil {
		return "", err
	}

	// Pre-flight uniqueness check: reject up front when another live account in the tenant already
	// owns the number. This is only advisory — the store's unique index is the authoritative guard
	// at confirm time, which closes the request->confirm race. Finding the *same* user (the number
	// is already theirs) is not a conflict; confirming would simply re-verify it.
	if existing, ferr := s.store.FindUserByPhone(ctx, tenantID, phone); ferr == nil {
		if existing.ID != userID {
			return "", ErrPhoneAlreadyExists
		}
	} else if !errors.Is(ferr, ErrUserNotFound) {
		return "", ferr
	}

	// Bind the requested number to the token as metadata. CreateVerificationToken also gates on
	// userID being a live, same-tenant account (returning ErrUserNotFound otherwise).
	token, err := s.store.CreateVerificationToken(ctx, tenantID, userID, KindPhoneVerification, s.phoneVerificationTTL, []byte(phone))
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmPhoneVerification consumes a phone-verification token and atomically sets the number.
func (s *service) ConfirmPhoneVerification(ctx context.Context, tenantID string, token string) (*User, error) {
	user, metadata, err := s.consumeForLiveUser(ctx, tenantID, token, KindPhoneVerification)
	if err != nil {
		return nil, err
	}

	// The token carries the (already-normalized) number. Re-normalize defensively rather than
	// trusting stored bytes blindly.
	phone, err := normalizePhone(string(metadata))
	if err != nil {
		return nil, err
	}

	now := s.now()
	// UpdateUserPhone is the atomic set point: it sets the user's phone and marks it verified in
	// one operation, enforcing phone uniqueness, so a number claimed since the token was minted
	// yields ErrPhoneAlreadyExists rather than a duplicate live number. Confirming a token
	// delivered to the number proves control of it, so it is marked verified.
	if err := s.store.UpdateUserPhone(ctx, tenantID, user.ID, phone, now); err != nil {
		return nil, err
	}
	user.Phone = &phone
	user.PhoneVerifiedAt = &now
	user.UpdatedAt = now
	s.emit(ctx, event.Event{Type: event.PhoneVerified, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// RecoveryChannels reports which INDEPENDENT, verified recovery channels an account has — i.e.
// channels other than the primary login email that can prove control during account recovery and
// gate sensitive operations. Use Any to decide whether a recovery/factor-reset is permitted.
type RecoveryChannels struct {
	// RecoveryEmail is true when a verified recovery email is enrolled.
	RecoveryEmail bool
	// Phone is true when a verified phone number is enrolled.
	Phone bool
}

// Any reports whether the account has at least one verified independent recovery channel.
func (rc RecoveryChannels) Any() bool {
	return rc.RecoveryEmail || rc.Phone
}

// RequestRecoveryEmail mints a token that, once confirmed, enrolls userID's recovery email.
func (s *service) RequestRecoveryEmail(ctx context.Context, tenantID string, userID uuid.UUID, recoveryEmail string) (string, error) {
	recoveryEmail, err := normalizeEmail(recoveryEmail)
	if err != nil {
		return "", err
	}

	// A recovery channel must be INDEPENDENT of the primary email — enrolling the primary address
	// as the recovery address would defeat the purpose (a single compromised mailbox would own
	// both). Gate on the live user up front (also yields ErrUserNotFound for unknown accounts).
	user, err := s.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	if user.DeletedAt != nil {
		return "", ErrUserNotFound
	}
	if recoveryEmail == user.Email {
		return "", ErrRecoveryEmailIsPrimary
	}

	// Bind the requested address to the token as metadata. CreateVerificationToken also re-checks
	// userID is a live, same-tenant account.
	token, err := s.store.CreateVerificationToken(ctx, tenantID, userID, KindRecoveryEmailVerification, s.recoveryEmailTTL, []byte(recoveryEmail))
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmRecoveryEmail consumes a recovery-email enrollment token and sets the recovery email.
func (s *service) ConfirmRecoveryEmail(ctx context.Context, tenantID string, token string) (*User, error) {
	user, metadata, err := s.consumeForLiveUser(ctx, tenantID, token, KindRecoveryEmailVerification)
	if err != nil {
		return nil, err
	}

	recoveryEmail, err := normalizeEmail(string(metadata))
	if err != nil {
		return nil, err
	}

	now := s.now()
	if err := s.store.UpdateUserRecoveryEmail(ctx, tenantID, user.ID, recoveryEmail, now); err != nil {
		return nil, err
	}
	user.RecoveryEmail = &recoveryEmail
	user.RecoveryEmailVerifiedAt = &now
	user.UpdatedAt = now
	s.emit(ctx, event.Event{Type: event.RecoveryChannelEnrolled, UserID: user.ID.String(), TenantID: user.TenantID})
	return user, nil
}

// RecoveryChannels reports the verified independent recovery channels enrolled for userID.
func (s *service) RecoveryChannels(ctx context.Context, tenantID string, userID uuid.UUID) (RecoveryChannels, error) {
	user, err := s.store.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return RecoveryChannels{}, err
	}
	if user.DeletedAt != nil {
		return RecoveryChannels{}, ErrUserNotFound
	}
	return recoveryChannelsOf(user), nil
}

// recoveryChannelsOf derives the verified-channel inventory from a loaded user.
func recoveryChannelsOf(user *User) RecoveryChannels {
	return RecoveryChannels{
		RecoveryEmail: user.RecoveryEmail != nil && *user.RecoveryEmail != "" && user.RecoveryEmailVerifiedAt != nil,
		Phone:         user.Phone != nil && *user.Phone != "" && user.PhoneVerifiedAt != nil,
	}
}

// RequestPasswordResetViaRecovery mints a reset token directed at a verified recovery channel.
func (s *service) RequestPasswordResetViaRecovery(ctx context.Context, tenantID string, email string) (string, *User, RecoveryChannels, error) {
	email, nerr := normalizeEmail(email)
	if nerr != nil {
		// Stay uniform: a malformed email behaves exactly like an unknown account.
		return "", nil, RecoveryChannels{}, nil
	}
	user, err := s.store.FindUserByEmail(ctx, tenantID, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", nil, RecoveryChannels{}, nil
		}
		return "", nil, RecoveryChannels{}, err
	}

	// Only an account that actually has a password can reset it (mirrors RequestPasswordReset);
	// stay uniform for OAuth-only accounts.
	idents, err := s.store.FindIdentitiesByUserID(ctx, tenantID, user.ID)
	if err != nil {
		return "", nil, RecoveryChannels{}, err
	}
	if !hasPasswordIdentity(idents) {
		return "", nil, RecoveryChannels{}, nil
	}

	// The whole point of this variant is to NOT trust the primary inbox: require a verified
	// independent recovery channel. Without one, stay enumeration-uniform (no token, no error) —
	// the caller cannot distinguish "no such account" from "no recovery channel".
	channels := recoveryChannelsOf(user)
	if !channels.Any() {
		return "", nil, RecoveryChannels{}, nil
	}

	token, err := s.store.CreateVerificationToken(ctx, tenantID, user.ID, KindPasswordReset, s.passwordResetTTL, nil)
	if err != nil {
		return "", nil, RecoveryChannels{}, err
	}
	return token, user, channels, nil
}

// DisableUser administratively suspends a live account: it stamps DisabledAt (so Authenticate
// returns ErrAccountDisabled and pending token-gated actions are revoked). It does not run the
// AccountErasers — active sessions/refresh tokens are not revoked by this call.
func (s *service) DisableUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if err := s.store.DisableUser(ctx, tenantID, userID, s.now()); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.AccountDisabled, UserID: userID.String(), TenantID: tenantID})
	return nil
}

// EnableUser re-activates an administratively disabled account by clearing DisabledAt.
func (s *service) EnableUser(ctx context.Context, tenantID string, userID uuid.UUID) error {
	if err := s.store.EnableUser(ctx, tenantID, userID); err != nil {
		return err
	}
	s.emit(ctx, event.Event{Type: event.AccountEnabled, UserID: userID.String(), TenantID: tenantID})
	return nil
}
