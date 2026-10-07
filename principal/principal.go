// Package principal exposes the read-only authentication vocabulary shared by applications, store
// implementations and egauth: tenants, subjects, factors and the sealed session attributes. Every
// type is an alias of the library's internal core, so none can be constructed or altered here;
// values are produced only by egauth itself.
//
// Beyond the aliases, it re-exports the constants returned by their accessors (factor roles,
// transports, caller kinds) so callers can compare them, and two functions that only delegate:
// ParseTenantID, the sole way to obtain a non-zero TenantID, and SealedFromBytes, which store
// implementations need to hand persisted bytes back without being able to decode them.
package principal

import "github.com/JLugagne/egauth/internal/core"

// TenantID identifies a tenant. The zero TenantID is the single tenant; any other value comes
// from ParseTenantID, so a slug or a user id cannot be passed as a tenant by accident.
type TenantID = core.TenantID

// ParseTenantID validates s as a tenant identifier: 1 to 128 bytes of ASCII letters, digits, '.',
// '_' or '-'. The empty string is refused; use the zero TenantID for the single tenant.
func ParseTenantID(s string) (TenantID, error) {
	return core.ParseTenantID(s)
}

// Subject identifies a user within a tenant: the same User under two tenants is two subjects.
// A Subject with a nil User is invalid everywhere.
type Subject = core.Subject

// SessionAttrs is the sealed state of an established session: subject, lineage, verified
// factors, freshness, must-change, remember-me, return target and transport. It is read through
// accessors only. Decide with HasFactor, MultiFactor and FreshWithin; AMR is for output only.
type SessionAttrs = core.SessionAttrs

// Factor is one authentication factor; compare it with the Factor* variables.
type Factor = core.Factor

// FactorRole classifies a factor as primary, second or qualifier.
type FactorRole = core.FactorRole

// Factor roles.
const (
	RolePrimary   = core.RolePrimary
	RoleSecond    = core.RoleSecond
	RoleQualifier = core.RoleQualifier
)

// The closed set of factors. FactorEmailLink is a magic link and is distinct from any one-time
// code factor.
var (
	FactorPassword         = core.FactorPassword
	FactorEmailLink        = core.FactorEmailLink
	FactorEmailCode        = core.FactorEmailCode
	FactorSMSCode          = core.FactorSMSCode
	FactorFederated        = core.FactorFederated
	FactorExternal         = core.FactorExternal
	FactorPasskey          = core.FactorPasskey
	FactorUserVerification = core.FactorUserVerification
	FactorTOTP             = core.FactorTOTP
	FactorRecoveryCode     = core.FactorRecoveryCode
	FactorPasskeyStepUp    = core.FactorPasskeyStepUp
)

// Transport is the channel a session's credentials travel on, sealed at login.
type Transport = core.Transport

// Session transports.
const (
	TransportCookies = core.TransportCookies
	TransportBearer  = core.TransportBearer
)

// Caller is the sealed identity of whoever invokes a facade method (session, API key or system).
type Caller = core.Caller

// CallerKind says who acts through a facade.
type CallerKind = core.CallerKind

// Caller kinds.
const (
	CallerSession = core.CallerSession
	CallerAPIKey  = core.CallerAPIKey
	CallerSystem  = core.CallerSystem
)

// Sealed is the opaque persisted form of session state. Stores keep its bytes verbatim and never
// decode them.
type Sealed = core.Sealed

// SealedFromBytes wraps bytes read back from storage into a Sealed, for store implementations.
// It copies b and does not validate it.
func SealedFromBytes(b []byte) Sealed {
	return core.SealedFromBytes(b)
}
