package issuance

import "errors"

var (
	// ErrNilIssuer is returned by New when no tokens.Issuer is supplied: there is nothing to
	// mint with.
	ErrNilIssuer = errors.New("issuance: a tokens.Issuer is required")

	// ErrMissingResolver is returned by New when no authoritative account-state resolver is
	// configured. The resolver is the validator the MFA gate relies on, so a pipeline without
	// one must never be built.
	ErrMissingResolver = errors.New("issuance: an authoritative account-state resolver is required")

	// ErrMFAWithoutValidator is returned by New when an MFA gate is configured without an
	// authoritative account-state resolver. The gate decides whether an enrolled user may
	// receive a full pair, so it must be paired with a validator that re-checks the account
	// lifecycle at issuance — mirroring the MFA gate / account validator pairing on the authflow
	// engine.
	ErrMFAWithoutValidator = errors.New("issuance: an MFA gate requires an authoritative account-state resolver (the account-lifecycle validator)")

	// ErrAccountDisabled is returned when the authoritative state reports an administratively
	// suspended account at issuance time.
	ErrAccountDisabled = errors.New("issuance: account is disabled")

	// ErrAccountDeleted is returned when the authoritative state reports a soft-deleted account
	// at issuance time.
	ErrAccountDeleted = errors.New("issuance: account is deleted")

	// ErrTenantMismatch is returned when the resolved account does not belong to the tenant the
	// caller requested. The pipeline never falls back to the empty partition.
	ErrTenantMismatch = errors.New("issuance: resolved account does not belong to the requested tenant")

	// ErrUserMismatch is returned when the authoritative state resolved a different user than
	// the one the caller asked to issue for.
	ErrUserMismatch = errors.New("issuance: resolved account does not match the requested user")
)
