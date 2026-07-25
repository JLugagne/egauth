package identity

import "errors"

var (
	// ErrUserNotFound is returned when a user cannot be found in the store.
	ErrUserNotFound = errors.New("identity: user not found")

	// ErrEmailAlreadyExists is returned when trying to create a user with an email
	// that already exists in the same tenant.
	ErrEmailAlreadyExists = errors.New("identity: email already exists")

	// ErrInvalidEmail is returned when an email fails RFC 5322 address parsing.
	ErrInvalidEmail = errors.New("identity: invalid email")

	// ErrEmailTooLong is returned when an address is longer than MaxEmailLength once
	// canonicalized. An oversized address is rejected by validation rather than handed to the
	// store, where it would fail late (e.g. on an index row-size limit) with an opaque error.
	ErrEmailTooLong = errors.New("identity: email too long")

	// ErrPhoneAlreadyExists is returned when trying to set a phone number that another
	// live account in the same tenant already owns.
	ErrPhoneAlreadyExists = errors.New("identity: phone already exists")

	// ErrInvalidPhone is returned when a phone number fails normalization (it is not a
	// plausible E.164 number: a leading '+' followed by 8–15 digits).
	ErrInvalidPhone = errors.New("identity: invalid phone")

	// ErrRecoveryEmailIsPrimary is returned when enrolling a recovery email equal to the
	// account's primary login email. A recovery channel must be INDEPENDENT of the primary
	// email to break the single-channel takeover chain, so the two may not coincide.
	ErrRecoveryEmailIsPrimary = errors.New("identity: recovery email must differ from the primary email")

	// ErrNoRecoveryChannel is returned by a recovery-channel-gated operation (e.g.
	// RequestPasswordResetViaRecovery) when the account has no VERIFIED independent recovery
	// channel enrolled (no verified recovery email and no verified phone).
	ErrNoRecoveryChannel = errors.New("identity: no verified recovery channel")

	// ErrIdentityNotFound is returned when an identity cannot be found.
	ErrIdentityNotFound = errors.New("identity: identity not found")

	// ErrIdentityAlreadyExists is returned when trying to create an identity
	// that already exists for a given provider and provider_id in a tenant.
	ErrIdentityAlreadyExists = errors.New("identity: identity already exists")

	// ErrTenantMismatch is returned by a Save/Create operation when the record already
	// carries a non-empty TenantID that differs from the tenantID argument passed to the call.
	ErrTenantMismatch = errors.New("identity: tenant ID mismatch")

	// ErrInvalidCredentials is returned when authentication fails due to invalid credentials.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrPasswordPolicyRequired is returned by a password operation
	// (Register/ResetPassword/ChangePassword) invoked on a Service constructed without a
	// passwords.Policy. A nil policy is legal for an OAuth-only deployment that uses no password
	// flows, so the operation fails fast with this clear error rather than panicking with a
	// nil-pointer dereference deep in the request.
	ErrPasswordPolicyRequired = errors.New("identity: password policy required for password operations")

	// ErrPasswordHasherRequired is returned by a password operation
	// (Register/ResetPassword/ChangePassword) invoked on a Service constructed without a
	// passwords.Hasher. Like ErrPasswordPolicyRequired, a nil hasher is legal for an OAuth-only
	// deployment, so the operation fails fast with this clear error instead of panicking.
	ErrPasswordHasherRequired = errors.New("identity: password hasher required for password operations")

	// ErrAccountLocked is returned when authentication is attempted on an account that is
	// currently locked due to too many failed attempts.
	ErrAccountLocked = errors.New("identity: account locked")

	// ErrAccountDisabled is returned when authentication is attempted on an account that an
	// administrator has disabled (suspended). Unlike ErrAccountLocked it does not clear on its
	// own after a duration: the account stays disabled until EnableUser is called.
	ErrAccountDisabled = errors.New("identity: account disabled")

	// ErrVerificationTokenNotFound is returned when a verification token cannot be found,
	// is malformed, or its verifier does not match. The three cases are deliberately
	// merged so the caller cannot distinguish "unknown selector" from "wrong verifier".
	ErrVerificationTokenNotFound = errors.New("identity: verification token not found")

	// ErrVerificationTokenExpired is returned when a verification token is found and its
	// verifier matches, but it is past its expiry. It is only surfaced to a caller that
	// presented the genuine token.
	ErrVerificationTokenExpired = errors.New("identity: verification token expired")

	// ErrDeliveryDropped is the Err carried by the DeliveryFailed event emitted when an
	// off-response-path delivery is dropped because the handler's delivery-concurrency cap
	// (WithDeliveryConcurrency) was already saturated. It is never returned to a caller — it
	// only surfaces through the event sink so an over-cap drop is observable like a Mailer
	// outage. See dispatchDelivery / WithDeliveryConcurrency.
	ErrDeliveryDropped = errors.New("identity: delivery dropped, concurrency cap exceeded")

	// ErrDeliveryPanic is joined into the Err of the DeliveryFailed event emitted when a
	// consumer Mailer/SMSSender callback PANICS on the off-response-path delivery goroutine.
	// The panic is recovered there — it would otherwise take the whole process down, since the
	// request has already left and no http.Server recovery covers that goroutine — and reported
	// through the event sink alongside the recovered value. It is never returned to a caller.
	ErrDeliveryPanic = errors.New("identity: delivery callback panicked")
)
