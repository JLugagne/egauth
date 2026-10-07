package event

// Event types introduced with the v0.17 composition object. Severity is documented per constant.
const (
	IdentifierChanged     Type = "identifier.changed"     // a contact identifier changed; Info
	SystemCallerUsed      Type = "system_caller.used"     // a facade ran under the system caller; Warn, carries the reason
	LimiterPerInstance    Type = "limiter.per_instance"   // an ephemeral limiter runs with shared stores; Info
	InsecureConfiguration Type = "configuration.insecure" // an acknowledged insecure setting; Warn, carries the reason
	MountMismatch         Type = "mount.mismatch"         // the handler is mounted behind a stripped prefix; Error
	ClaimsUnavailable     Type = "claims.unavailable"     // the claims source failed at admission; Error
	ClaimsStale           Type = "claims.stale"           // stale claims were kept for one renewal period; Warn
	ClaimsTooLarge        Type = "claims.too_large"       // encoded application claims exceed the limit; Error
	MFAModuleMissing      Type = "mfa.module_missing"     // a required factor has no enabled completing module; Error
	ProxyHeadersIgnored   Type = "proxy.headers_ignored"  // forwarding headers from a private peer were ignored; Warn
	LifecycleRetry        Type = "lifecycle.retry"        // an outbox effect failed and will be retried; Error
	RevocationUnavailable Type = "revocation.unavailable" // the revocation store was unreachable; Error
)

// V17Types returns the types added by this file.
func V17Types() []Type {
	return []Type{
		IdentifierChanged, SystemCallerUsed, LimiterPerInstance, InsecureConfiguration, MountMismatch,
		ClaimsUnavailable, ClaimsStale, ClaimsTooLarge, MFAModuleMissing, ProxyHeadersIgnored,
		LifecycleRetry, RevocationUnavailable,
	}
}
