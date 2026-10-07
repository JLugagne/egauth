package core

import "errors"

var (
	// ErrInvalidTenant is returned by ParseTenantID for an empty or malformed tenant identifier.
	ErrInvalidTenant = errors.New("core: invalid tenant id")
	// ErrInvalidFactor is returned for the zero Factor, an unknown code, or a factor used in a role
	// that the transition does not accept.
	ErrInvalidFactor = errors.New("core: invalid factor")
	// ErrInvalidVerified is returned for a Verified that violates the factor shape rules.
	ErrInvalidVerified = errors.New("core: invalid verified factor")
	// ErrInvalidArgument is returned for a zero or out-of-range enum, an invalid Subject, or a zero
	// SessionAttrs passed to a transition.
	ErrInvalidArgument = errors.New("core: invalid argument")
	// ErrTenantMismatch is returned when a value of one tenant is applied to another tenant.
	ErrTenantMismatch = errors.New("core: tenant mismatch")
	// ErrSubjectMismatch is returned when a factor or session of one subject is applied to a
	// Pending or SessionAttrs bound to another subject (C-29).
	ErrSubjectMismatch = errors.New("core: subject mismatch")
	// ErrNotBound is returned when a second factor is added to, or admission is attempted on, a
	// Pending that no identifying factor has bound to a subject.
	ErrNotBound = errors.New("core: pending is not bound to a subject")
	// ErrAlreadyBound is returned by Pending.Bind on a Pending already bound to a subject.
	ErrAlreadyBound = errors.New("core: pending is already bound")
	// ErrNotIdentifying is returned when a non-identifying factor is added to an unbound Pending.
	ErrNotIdentifying = errors.New("core: factor does not identify a subject")
	// ErrSameCredential is returned when a passkey step-up reuses the credential of the primary
	// passkey of the same Pending (C-28).
	ErrSameCredential = errors.New("core: second factor reuses the primary credential")
	// ErrProviderMismatch is returned when a Pending would mix two federation providers.
	ErrProviderMismatch = errors.New("core: provider mismatch")
	// ErrNoPrimary is returned when admission or reauthentication has no primary factor.
	ErrNoPrimary = errors.New("core: no primary factor")
	// ErrPendingExpired is returned when a Pending is used at or after its expiry.
	ErrPendingExpired = errors.New("core: pending expired")
	// ErrReauthPending is returned by Admit for a Pending created by PendingForReauth.
	ErrReauthPending = errors.New("core: reauthentication pending cannot start a session")
	// ErrLineageMismatch is returned by Reauthenticate when the Pending was not created for the
	// session being reauthenticated.
	ErrLineageMismatch = errors.New("core: lineage mismatch")
	// ErrAccountUnusable is returned when the account does not exist, is disabled or is deleted.
	ErrAccountUnusable = errors.New("core: account does not exist, is disabled or deleted")
	// ErrEpochStale is returned when the security epoch sealed in a session or Pending is not the
	// subject's current epoch: a security change happened since it was established (D2).
	ErrEpochStale = errors.New("core: security epoch is stale")
	// ErrReauthRequired is returned by Renew when the subject is enrolled in MFA and the session is
	// not multi-factor; the session must not be extended.
	ErrReauthRequired = errors.New("core: reauthentication required")
	// ErrFactorRequired is returned by Reauthenticate when the subject is enrolled in MFA and the
	// reauthentication is not multi-factor yet.
	ErrFactorRequired = errors.New("core: second factor required")
	// ErrClaimsUnavailable is returned by Renew when the claims source failed past the staleness
	// bound.
	ErrClaimsUnavailable = errors.New("core: claims unavailable")
	// ErrClaimsSubjectUnknown is returned by Renew when the claims source no longer knows the
	// subject; the session must be revoked.
	ErrClaimsSubjectUnknown = errors.New("core: claims source does not know the subject")
	// ErrClaimsTooLarge is returned by Renew when the encoded claims exceed their bound.
	ErrClaimsTooLarge = errors.New("core: claims too large")
	// ErrMalformed is returned by the codec for bytes that are not a canonical v1 encoding.
	ErrMalformed = errors.New("core: malformed sealed value")
)
