package event

// Severity ranks how much attention an event deserves. Sinks map it to their own level or status.
type Severity uint8

const (
	// SeverityInfo marks a routine lifecycle event.
	SeverityInfo Severity = iota + 1
	// SeverityWarn marks an anomaly or a failed security check that does not break the service.
	SeverityWarn
	// SeverityError marks a malfunction or misconfiguration that needs an operator.
	SeverityError
)

// String returns the lowercase name of s, or "invalid".
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	}
	return "invalid"
}

// Severity returns the fixed severity of t. A type missing from the switch is reported as
// SeverityError so that an unclassified event is never understated; the exhaustiveness test
// keeps that branch unreachable for declared constants.
func (t Type) Severity() Severity {
	switch t {
	case LoginSucceeded, SessionIssued, UserRegistered, PasswordReset, PasswordChanged, EmailVerified,
		EmailChanged, PhoneVerified, RecoveryChannelEnrolled, AccountDeleted, Logout, AccountDisabled,
		AccountEnabled, MFAChallengeRequired, MFAEnrolled, MFAConfirmed, MFAVerified, MFADisabled,
		MFAUnlocked, CredentialAdded, CredentialRemoved, APIKeyCreated, APIKeyRevoked,
		APIKeyAuthSucceeded, APIKeyPurged, IdentifierChanged, LimiterPerInstance:
		return SeverityInfo
	case LoginFailed, AccountLocked, AccountBlocked, RefreshReuseDetected, TokenFamilyRevoked,
		MFAVerificationFailed, APIKeyAuthFailed, DeliveryFailed, InsecureCookieMisuse,
		RedirectFallbackMisuse, SystemCallerUsed, InsecureConfiguration, ClaimsStale, ProxyHeadersIgnored:
		return SeverityWarn
	case MountMismatch, ClaimsUnavailable, ClaimsTooLarge, MFAModuleMissing, LifecycleRetry,
		RevocationUnavailable:
		return SeverityError
	}
	return SeverityError
}
